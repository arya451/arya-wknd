package com.adobe.aem.guides.wknd.core.servlets;

import com.day.cq.search.PredicateGroup;
import com.day.cq.search.Query;
import com.day.cq.search.QueryBuilder;
import com.day.cq.search.result.Hit;
import com.day.cq.search.result.SearchResult;
import com.google.gson.Gson;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ValueMap;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.json.JSONArray;
import org.json.JSONObject;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.jcr.security.AccessControlManager;
import javax.jcr.security.Privilege;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.IOException;
import java.security.Principal;
import java.util.*;

@Component(service = Servlet.class)
@SlingServletPaths("/bin/asset-entitlements")
@ServiceDescription("Asset Entitlement Servlet")
public class AssetEntitlementServlet extends SlingSafeMethodsServlet {

    private static final Logger log = LoggerFactory.getLogger(AssetEntitlementServlet.class);
    private static final long serialVersionUID = 1L;
    private static final String SUBSERVICE = "jigsawServiceUser";

    @Reference
    private ResourceResolverFactory resolverFactory;

    @Reference
    private QueryBuilder queryBuilder;

    @Override
    protected void doGet(SlingHttpServletRequest request, SlingHttpServletResponse response)
            throws ServletException, IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String userId = request.getParameter("userId");
        String rootPath = request.getParameter("rootPath");

        if (userId == null || rootPath == null) {
            response.setStatus(SlingHttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("{\"error\":\"Missing required parameters: userId, rootPath\"}");
            return;
        }

        try (ResourceResolver serviceResolver = getServiceResolver()) {
            Session serviceSession = serviceResolver.adaptTo(Session.class);

            // Impersonate the target user from the service session
            Session userSession = serviceSession.impersonate(
                    new SimpleCredentials(userId, new char[0]));

            // Wrap userSession into a ResourceResolver
            Map<String, Object> authInfo = new HashMap<>();
            authInfo.put("user.jcr.session", userSession);
            try (ResourceResolver userResolver = resolverFactory.getResourceResolver(authInfo)) {
                Map<String, String> map = new HashMap<>();
                map.put("type", "dam:Asset");
                map.put("path", rootPath);
                map.put("1_property", "jcr:content/contentFragment");
                map.put("1_property.value", "true");
                map.put("p.limit", "-1");
                map.put("p.guessTotal", "true");

                SearchResult searchResult = queryBuilder
                        .createQuery(PredicateGroup.create(map), userSession)
                        .getResult();

                List<String> paths = new ArrayList<>();
                for (Hit hit : searchResult.getHits()) {
                    paths.add(hit.getPath());
                }

                Map<String, Object> result = new LinkedHashMap<>();
                result.put("userId", userId);
                result.put("rootPath", rootPath);
                result.put("count", paths.size());
                result.put("assets", paths);

                response.setStatus(SlingHttpServletResponse.SC_OK);
                response.getWriter().write(new Gson().toJson(result));
            } finally {
                userSession.logout(); // important — impersonated sessions must be manually closed
            }
        } catch (LoginException le) {
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"LoginException: " + le.getMessage() + "\"}");
        } catch (Exception e) {
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    private ResourceResolver getServiceResolver() throws LoginException {
        Map<String, Object> params = new HashMap<>();
        params.put(ResourceResolverFactory.SUBSERVICE, SUBSERVICE);
        return resolverFactory.getServiceResourceResolver(params);
    }
}