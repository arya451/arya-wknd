/*
 *  Copyright 2015 Adobe Systems Incorporated
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.adobe.aem.guides.wknd.core.servlets;

import com.google.gson.Gson;

import org.apache.jackrabbit.api.security.JackrabbitAccessControlManager;
import org.apache.sling.api.SlingHttpServletRequest;
import org.apache.sling.api.SlingHttpServletResponse;
import org.apache.sling.api.resource.Resource;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.api.servlets.SlingAllMethodsServlet;
import org.apache.sling.api.servlets.SlingSafeMethodsServlet;
import org.apache.sling.servlets.annotations.SlingServletPaths;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.propertytypes.ServiceDescription;

import javax.jcr.query.QueryManager;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import java.io.IOException;
import javax.jcr.Session;
import javax.jcr.Node;
import java.util.*;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.api.security.user.Authorizable;

import javax.jcr.query.Query;
import javax.jcr.query.QueryResult;

import java.security.Principal;
import javax.jcr.NodeIterator;
import javax.jcr.security.Privilege;

/**
 * Servlet that writes some sample content into the response. It is mounted for
 * all resources of a specific Sling resource type. The
 * {@link SlingSafeMethodsServlet} shall be used for HTTP methods that are
 * idempotent. For write operations use the {@link SlingAllMethodsServlet}.
 */
@Component(service = { Servlet.class })
@SlingServletPaths("/bin/user-folder-access")
@ServiceDescription("Simple Demo Servlet")
public class JigsawModules extends SlingSafeMethodsServlet {

    @Reference
    private ResourceResolverFactory resolverFactory;

    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(final SlingHttpServletRequest request,
            final SlingHttpServletResponse response) throws ServletException, IOException {
        String userId = request.getParameter("userId");
        String rootPath = request.getParameter("folderPath");

        // Map<String, Object> serviceAuth = new HashMap<>();
        // serviceAuth.put(ResourceResolverFactory.SUBSERVICE, "folder-access-service");
        final Resource resource = request.getResource();

        try (ResourceResolver resolver =
                     request.getResourceResolver()) {

            Session session = resolver.adaptTo(Session.class);
            UserManager userManager = resolver.adaptTo(UserManager.class);

            Authorizable authorizable = userManager.getAuthorizable(userId);
            Principal principal = authorizable.getPrincipal();

            JackrabbitAccessControlManager acm =
                    (JackrabbitAccessControlManager) session.getAccessControlManager();

            List<String> accessibleFolders = new ArrayList<>();

            String query = "SELECT * FROM [sling:Folder] AS s WHERE ISDESCENDANTNODE(s,'" + rootPath + "')";

            QueryManager qm = session.getWorkspace().getQueryManager();
            Query jcrQuery = qm.createQuery(query, Query.JCR_SQL2);

            QueryResult result = jcrQuery.execute();

            NodeIterator nodes = result.getNodes();

            while (nodes.hasNext()) {

                Node node = nodes.nextNode();
                String path = node.getPath();
                
                Privilege[] privileges = acm.getPrivileges(path, Collections.singleton(principal)); 
                boolean allowed = privileges.length > 0;
                if (allowed) {
                    accessibleFolders.add(path);
                }
            }   
            response.setContentType("application/json");
            response.getWriter().write(new Gson().toJson(accessibleFolders));
        } catch (Exception e) {
            response.getWriter().write("Error: " + e.getMessage());
        }
        
    }
}
