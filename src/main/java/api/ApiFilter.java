package api;

import common.ResourcesUtil;
import common.ResponseUtil;
import common.TokenUtil;
import org.glassfish.jersey.server.ContainerRequest;

import javax.annotation.Priority;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.ws.rs.Priorities;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.container.ContainerRequestContext;
import javax.ws.rs.container.ContainerRequestFilter;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.ext.Provider;
import java.io.IOException;
import java.util.logging.Logger;

/**
 * Created by Thuan.Evi on 1/3/2017.
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class ApiFilter implements ContainerRequestFilter {

    final static Logger logger = Logger.getLogger(ApiFilter.class.getName());

    @Context
    HttpServletRequest httpRequest;

    @Override
    public void filter(ContainerRequestContext containerRequestContext) throws IOException {

        HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            session = httpRequest.getSession(true);
            session.setMaxInactiveInterval(24 * 60 * 60); // 24 hours
            session.setAttribute("realPath", httpRequest.getServletContext().getRealPath("/"));
        }

        String acceptLanguage = containerRequestContext.getHeaderString("accept-language");
        if (acceptLanguage == null || !(acceptLanguage.equals("en") && acceptLanguage.equals("jp")))
            acceptLanguage = "en";
        session.setAttribute("acceptLanguage", acceptLanguage);

        ResourcesUtil resourcesUtil = ResourcesUtil.getInstance(httpRequest);
        ResponseUtil responseUtil = resourcesUtil.getMessage("MSG1");
        if (responseUtil.getStatus() == false) {
            throw new WebApplicationException(Response
                    .status(Response.Status.UNAUTHORIZED)
                    .entity(responseUtil.getErrMessage())
                    .build());
        }
        String unauthorized = responseUtil.getStringData();

        String authorization = containerRequestContext.getHeaderString("authorization");
        if (authorization == null) {
            logger.info(unauthorized);
            throw new WebApplicationException(Response
                    .status(Response.Status.UNAUTHORIZED)
                    .entity(unauthorized)
                    .build());
        }

        final String method = containerRequestContext.getMethod().toLowerCase();
        final String path = ((ContainerRequest) containerRequestContext).getPath(true).toLowerCase();
        if ("post".equals(method) && "user/authenticate".equals(path)) {

            String base64Credentials = authorization.substring("Basic".length()).trim();
            responseUtil = TokenUtil.getInstance(httpRequest).base64DecodeToString(base64Credentials);
            if (responseUtil.getStatus() == false) {
                logger.info(unauthorized);
                throw new WebApplicationException(Response
                        .status(Response.Status.UNAUTHORIZED)
                        .entity(unauthorized)
                        .build());
            }
            String credentials = responseUtil.getStringData();
            session.setAttribute("credentials", credentials);
            return;
        }

        if (session == null || session.getAttribute("credentials") == null) {
            logger.info(unauthorized);
            throw new WebApplicationException(Response
                    .status(Response.Status.UNAUTHORIZED)
                    .entity(unauthorized)
                    .build());
        }

        responseUtil = TokenUtil.getInstance(httpRequest).jwtVerifier(authorization);
        if (responseUtil.getStatus() == true)
            return;

        logger.info(unauthorized);
        throw new WebApplicationException(Response
                .status(Response.Status.UNAUTHORIZED)
                .entity(unauthorized)
                .build());
    }

}
