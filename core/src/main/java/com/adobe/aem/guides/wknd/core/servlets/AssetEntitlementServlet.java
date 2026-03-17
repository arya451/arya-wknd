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

import javax.jcr.Session;
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

        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        String userId   = request.getParameter("userId");
        String rootPath = request.getParameter("rootPath");

        if (userId == null || rootPath == null) {
            response.setStatus(SlingHttpServletResponse.SC_BAD_REQUEST);
            response.getWriter().write("{\"error\":\"Missing required parameters: userId, rootPath\"}");
            return;
        }

        try (ResourceResolver serviceResolver = getServiceResolver()) {

            log.error("=== STEP 1: Service resolver userId=[{}] ===",
                    serviceResolver.getUserID());

            // -----------------------------------------------
            // Step 1: Resolve user
            // -----------------------------------------------
            UserManager userManager = serviceResolver.adaptTo(UserManager.class);
            if (userManager == null) {
                response.getWriter().write("{\"error\":\"Cannot adapt to UserManager\"}");
                return;
            }

            Authorizable authorizable = userManager.getAuthorizable(userId);
            if (authorizable == null) {
                response.setStatus(SlingHttpServletResponse.SC_NOT_FOUND);
                response.getWriter().write("{\"error\":\"No user found for userId: " + userId + "\"}");
                return;
            }

            Principal principal = authorizable.getPrincipal();
            log.error("=== STEP 1 OK: principal=[{}] path=[{}] ===",
                    principal.getName(), authorizable.getPath());

            // -----------------------------------------------
            // Step 2: Query content fragments
            // -----------------------------------------------
            Session serviceSession = serviceResolver.adaptTo(Session.class);

            Map<String, String> queryMap = new HashMap<>();
            queryMap.put("type", "dam:Asset");
            queryMap.put("path", rootPath);
            queryMap.put("1_property", "jcr:content/contentFragment");
            queryMap.put("1_property.value", "true");
            queryMap.put("p.limit", "-1");
            queryMap.put("p.guessTotal", "true");

            Query query = queryBuilder.createQuery(PredicateGroup.create(queryMap), serviceSession);
            SearchResult searchResult = query.getResult();

            long totalHits = searchResult.getTotalMatches();
            log.error("=== STEP 2: Query hits=[{}] ===", totalHits);

            if (totalHits == 0) {
                log.error("=== STEP 2 WARN: No content fragments found under path=[{}]. " +
                        "Check if assets have jcr:content/contentFragment=true ===", rootPath);
            }

            // -----------------------------------------------
            // Step 3: Check entitlement per asset
            // -----------------------------------------------
            JackrabbitAccessControlManager acm =
                    (JackrabbitAccessControlManager) serviceSession.getAccessControlManager();

            List<Map<String, String>> assets = new ArrayList<>();

            for (Hit hit : searchResult.getHits()) {
                String assetPath = hit.getPath();
                String folderPath = assetPath.substring(0, assetPath.lastIndexOf("/"));

                log.error("=== STEP 3: Checking asset=[{}] folderPath=[{}] ===",
                        assetPath, folderPath);

                // --- RAW privileges dump ---
                try {
                    Privilege[] rawPrivileges = acm.getPrivileges(
                            folderPath, Collections.singleton(principal));

                    log.error("  RAW privileges count=[{}] for principal=[{}] on folderPath=[{}]",
                            rawPrivileges.length, principal.getName(), folderPath);

                    for (Privilege p : rawPrivileges) {
                        log.error("  RAW privilege: name=[{}] isAggregate=[{}]",
                                p.getName(), p.isAggregate());
                    }

                    // --- Expanded privileges dump ---
                    Set<String> expanded = new HashSet<>();
                    expandPrivileges(rawPrivileges, expanded);
                    log.error("  EXPANDED privileges: {}", expanded);

                } catch (Exception ex) {
                    log.error("  ERROR calling getPrivileges: {}", ex.getMessage(), ex);
                }

                // --- Also try on asset path directly ---
                try {
                    Privilege[] assetPrivs = acm.getPrivileges(
                            assetPath, Collections.singleton(principal));
                    log.error("  ASSET PATH privileges count=[{}] on assetPath=[{}]",
                            assetPrivs.length, assetPath);
                    for (Privilege p : assetPrivs) {
                        log.error("  ASSET privilege: name=[{}]", p.getName());
                    }
                } catch (Exception ex) {
                    log.error("  ERROR calling getPrivileges on assetPath: {}", ex.getMessage(), ex);
                }

                String entitlement = computeEntitlement(acm, folderPath, principal);
                log.error("=== STEP 3 RESULT: entitlement=[{}] for userId=[{}] ===",
                        entitlement, userId);

                if (!"none".equals(entitlement)) {
                    Resource assetRes = serviceResolver.getResource(assetPath);
                    String title = "";
                    if (assetRes != null) {
                        Resource metaRes = assetRes.getChild("jcr:content/metadata");
                        ValueMap meta = metaRes != null ? metaRes.getValueMap() : ValueMap.EMPTY;
                        title = meta.get("dc:title", "");
                    }

                    Map<String, String> assetInfo = new LinkedHashMap<>();
                    assetInfo.put("path", assetPath);
                    assetInfo.put("title", title);
                    assetInfo.put("entitlement", entitlement);
                    assets.add(assetInfo);
                }
            }

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("userId", userId);
            result.put("rootPath", rootPath);
            result.put("count", assets.size());
            result.put("assets", assets);

            response.setStatus(SlingHttpServletResponse.SC_OK);
            response.getWriter().write(new Gson().toJson(result));

        } catch (LoginException le) {
            log.error("LoginException: {}", le.getMessage(), le);
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"LoginException: " + le.getMessage() + "\"}");
        } catch (Exception e) {
            log.error("Exception in AssetEntitlementServlet: {}", e.getMessage(), e);
            response.setStatus(SlingHttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            response.getWriter().write("{\"error\":\"" + e.getClass().getSimpleName() + ": " + e.getMessage() + "\"}");
        }
    }

    private String computeEntitlement(JackrabbitAccessControlManager acm,
                                      String folderPath,
                                      Principal principal) {
        try {
            Privilege[] privileges = acm.getPrivileges(folderPath, Collections.singleton(principal));
            if (privileges == null || privileges.length == 0) return "none";

            Set<String> privNames = new HashSet<>();
            expandPrivileges(privileges, privNames);

            // Check both aggregate names AND their Oak-expanded equivalents
            if (privNames.contains(Privilege.JCR_REMOVE_NODE)
                    || privNames.contains("rep:write")
                    || privNames.contains("jcr:removeNode")) return "own";

            if (privNames.contains(Privilege.JCR_WRITE)
                    || privNames.contains(Privilege.JCR_MODIFY_PROPERTIES)
                    || privNames.contains("rep:addProperties")
                    || privNames.contains("jcr:modifyProperties")) return "edit";

            // jcr:read expands to rep:readProperties + rep:readNodes in Oak
            if (privNames.contains(Privilege.JCR_READ)
                    || privNames.contains("rep:readProperties")
                    || privNames.contains("rep:readNodes")) return "view";

        } catch (Exception e) {
            log.warn("Could not compute entitlement for path=[{}]: {}", folderPath, e.getMessage());
        }
        return "none";
    }

    private void expandPrivileges(Privilege[] privileges, Set<String> result) {
        for (Privilege p : privileges) {
            if (p.isAggregate()) {
                expandPrivileges(p.getAggregatePrivileges(), result);
            } else {
                result.add(p.getName());
            }
        }
    }

    private ResourceResolver getServiceResolver() throws LoginException {
        Map<String, Object> params = new HashMap<>();
        params.put(ResourceResolverFactory.SUBSERVICE, SUBSERVICE);
        return resolverFactory.getServiceResourceResolver(params);
    }
}