package com.adobe.aem.guides.wknd.core.servlets;

import com.day.cq.search.PredicateGroup;
import com.day.cq.search.QueryBuilder;
import com.day.cq.search.result.Hit;
import com.day.cq.search.result.SearchResult;
import com.google.gson.Gson;
import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.jackrabbit.api.security.user.Authorizable;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.propertytypes.ServiceDescription;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.jcr.Session;
import javax.jcr.security.Privilege;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.IOException;
import java.security.Principal;
import java.util.*;

@Component(service = Servlet.class)
@SlingServletPaths("/bin/asset-entitlement-manual")
@ServiceDescription("Asset Entitlement Servlet Manual")
public class AssetEntitlementManual extends SlingSafeMethodsServlet {

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

            // 1. Look up the target user and get their principals
            UserManager userManager = serviceResolver.adaptTo(UserManager.class);
            Authorizable authorizable = userManager.getAuthorizable(userId);
            if (authorizable == null) {
                response.setStatus(SlingHttpServletResponse.SC_BAD_REQUEST);
                response.getWriter().write("{\"error\":\"User not found: " + userId + "\"}");
                return;
            }

            // Collect user's principal + all group principals
            Set<Principal> principals = new HashSet<>();
            principals.add(authorizable.getPrincipal());
            Iterator<org.apache.jackrabbit.api.security.user.Group> groups = authorizable.memberOf();
            while (groups.hasNext()) {
                principals.add(groups.next().getPrincipal());
            }

            // 2. Query ALL content fragments under rootPath using service session
            Map<String, String> queryMap = new HashMap<>();
            queryMap.put("type", "dam:Asset");
            queryMap.put("path", rootPath);
            queryMap.put("1_property", "jcr:content/contentFragment");
            queryMap.put("1_property.value", "true");
            queryMap.put("p.limit", "-1");
            queryMap.put("p.guessTotal", "true");

            SearchResult searchResult = queryBuilder
                    .createQuery(PredicateGroup.create(queryMap), serviceSession)
                    .getResult();

            // 3. Filter results by checking ACL for the target user
            JackrabbitAccessControlManager acm =
                    (JackrabbitAccessControlManager) serviceSession.getAccessControlManager();
            Privilege[] readPrivilege = new Privilege[]{
                    acm.privilegeFromName(Privilege.JCR_READ)
            };

            List<String> accessiblePaths = new ArrayList<>();
            for (Hit hit : searchResult.getHits()) {
                String path = hit.getPath();
                if (acm.hasPrivileges(path, principals, readPrivilege)) {
                    accessiblePaths.add(path);
                }
            }

            // 4. Build and return JSON response
            Map<String, Object> result = new LinkedHashMap<>();
            result.put("userId", userId);
            result.put("rootPath", rootPath);
            result.put("count", accessiblePaths.size());
            result.put("assets", accessiblePaths);

            response.setStatus(SlingHttpServletResponse.SC_OK);
            response.getWriter().write(new Gson().toJson(result));

        } catch (LoginException e) {
            log.error("Service login failed", e);
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"Service login failed\"}");
        } catch (RepositoryException e) {
            log.error("Repository error while checking entitlements", e);
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"Repository error while checking entitlements\"}");
        } catch (Exception e) {
            log.error("Unexpected error", e);
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"Unexpected error\"}");
        }
    }

    private ResourceResolver getServiceResolver() throws LoginException {
        Map<String, Object> params = new HashMap<>();
        params.put(ResourceResolverFactory.SUBSERVICE, SUBSERVICE);
        return resolverFactory.getServiceResourceResolver(params);
    }
}