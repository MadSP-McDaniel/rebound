# Simple test application for rollback server demo
FROM nginx:alpine

# Copy a simple HTML page
COPY <<EOF /usr/share/nginx/html/index.html
<!DOCTYPE html>
<html>
<head>
    <title>Secure Deployment Demo</title>
</head>
<body>
    <h1>🚀 Secure Deployment with Rollback</h1>
    <p>This application was deployed using a secure rollback server with rollback capabilities.</p>
    <p>Build time: $(date)</p>
    <p>Commit: $BUILD_COMMIT</p>
</body>
</html>
EOF

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
