addEventListener("fetch", (event) => {
  event.passThroughOnException();
  event.respondWith(handleRequest(event.request));
});

const dockerHub = "https://registry-1.docker.io";

function routeByPath(path) {
  const pathSeg = path.split("/")[1];
  switch (pathSeg) {
    case "ghcr.io":
      return "https://ghcr.io";
    case "quay.io":
      return "https://quay.io";
    case "gcr.io":
      return "https://gcr.io";
    case "k8s-gcr.io":
      return "https://k8s.gcr.io";
    case "k8s.io":
      return "https://registry.k8s.io";
    case "cloudsmith.io":
      return "https://docker.cloudsmith.io";
    case "public.ecr.aws":
      return "https://public.ecr.aws";
    default:
      return dockerHub;
  }
}

async function handleRequest(request) {
  const url = new URL(request.url);
  const upstream = routeByPath(url.pathname);
  if (!upstream) {
    return new Response(JSON.stringify({ message: "NOT FOUND" }), { status: 404 });
  }
  const isDockerHub = upstream == dockerHub;
  const authorization = request.headers.get("Authorization");
  if (url.pathname == "/v2/") {
    const newUrl = new URL(upstream + "/v2/");
    const headers = new Headers();
    if (authorization) {
      headers.set("Authorization", authorization);
    }
    // check if need to authenticate
    const resp = await fetch(newUrl.toString(), {
      method: "GET",
      headers: headers,
      redirect: "follow",
    });
    if (resp.status === 401) {
      const authenticateStr = resp.headers.get("WWW-Authenticate");
      if (!authenticateStr) {
        return responseUnauthorized(url);
      }
      const wwwAuthenticate = parseAuthenticate(authenticateStr);
      let scope = url.searchParams.get("scope");
      // autocomplete repo part into scope for DockerHub library images
      // Example: repository:busybox:pull => repository:library/busybox:pull
      if (scope && isDockerHub) {
        let scopeParts = scope.split(":");
        if (scopeParts.length == 3 && !scopeParts[1].includes("/")) {
          scopeParts[1] = "library/" + scopeParts[1];
          scope = scopeParts.join(":");
        }
      }
      const tokenResp = await fetchToken(wwwAuthenticate, scope, authorization);
      if (!tokenResp.ok) {
        return responseUnauthorized(url);
      }
      const tokenBody = await tokenResp.json();
      const token = tokenBody.token || tokenBody.access_token;
      const newHeaders = new Headers(request.headers);
      newHeaders.set("Authorization", `Bearer ${token}`);
      const retryReq = new Request(newUrl, {
        method: request.method,
        headers: newHeaders,
        redirect: isDockerHub ? "manual" : "follow",
      });
      return fetch(retryReq);
    }
    return resp;
  }
  // redirect for DockerHub library images
  if (isDockerHub) {
    const pathParts = url.pathname.split("/");
    if (pathParts.length == 5) {
      pathParts.splice(2, 0, "library");
      const redirectUrl = new URL(url);
      redirectUrl.pathname = pathParts.join("/");
      return Response.redirect(redirectUrl, 301);
    }
  }
  // foward requests
  const newUrl = new URL(upstream + url.pathname);
  const newReq = new Request(newUrl, {
    method: request.method,
    headers: request.headers,
    // don't follow redirect to dockerhub blob upstream
    redirect: isDockerHub ? "manual" : "follow",
  });
  const resp = await fetch(newReq);
  if (resp.status == 401) {
    const authenticateStr = resp.headers.get("WWW-Authenticate");
    if (!authenticateStr) {
      return responseUnauthorized(url);
    }
    const wwwAuthenticate = parseAuthenticate(authenticateStr);
    let scope = url.searchParams.get("scope");
    // autocomplete repo part into scope for DockerHub library images
    // Example: repository:busybox:pull => repository:library/busybox:pull
    if (scope && isDockerHub) {
      let scopeParts = scope.split(":");
      if (scopeParts.length == 3 && !scopeParts[1].includes("/")) {
        scopeParts[1] = "library/" + scopeParts[1];
        scope = scopeParts.join(":");
      }
    }
    const tokenResp = await fetchToken(wwwAuthenticate, scope, authorization);
    if (!tokenResp.ok) {
      return responseUnauthorized(url);
    }
    const tokenBody = await tokenResp.json();
    const token = tokenBody.token || tokenBody.access_token;
    const newHeaders = new Headers(request.headers);
    newHeaders.set("Authorization", `Bearer ${token}`);
    const retryReq = new Request(newUrl, {
      method: request.method,
      headers: newHeaders,
      redirect: isDockerHub ? "manual" : "follow",
    });
    return fetch(retryReq);
  }
  // handle dockerhub blob redirect manually
  if (isDockerHub && resp.status == 307) {
    const location = new URL(resp.headers.get("Location"));
    const redirectResp = await fetch(location.toString(), {
      method: "GET",
      redirect: "follow",
    });
    return redirectResp;
  }
  return resp;
}

function parseAuthenticate(authenticateStr) {
  // sample: Bearer realm="https://auth.ipv6.docker.com/token",service="registry.docker.io"
  // match strings after =" and before "
  const re = /(?<=\=")(?:\\.|[^"\\])*(?=")/g;
  const matches = authenticateStr.match(re);
  if (matches == null || matches.length < 2) {
    throw new Error(`invalid Www-Authenticate Header: ${authenticateStr}`);
  }
  return {
    realm: matches[0],
    service: matches[1],
  };
}

async function fetchToken(wwwAuthenticate, scope, authorization) {
  const url = new URL(wwwAuthenticate.realm);
  if (wwwAuthenticate.service.length) {
    url.searchParams.set("service", wwwAuthenticate.service);
  }
  if (scope) {
    url.searchParams.set("scope", scope);
  }
  const headers = new Headers();
  if (authorization) {
    headers.set("Authorization", authorization);
  }
  return await fetch(url, { method: "GET", headers: headers });
}

function responseUnauthorized(url) {
  const headers = new(Headers);
  if (MODE == "debug") {
    headers.set(
      "Www-Authenticate",
      `Bearer realm="http://${url.host}/v2/auth",service="cloudflare-docker-proxy"`
    );
  } else {
    headers.set(
      "Www-Authenticate",
      `Bearer realm="https://${url.hostname}/v2/auth",service="cloudflare-docker-proxy"`
    );
  }
  return new Response(JSON.stringify({ message: "UNAUTHORIZED" }), {
    status: 401,
    headers: headers,
  });
}
