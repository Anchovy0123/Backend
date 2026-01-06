// swagger.js
const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const path = require("path");

const options = {
  definition: {
    openapi: "3.0.0",
    info: { title: "BackEnd API", version: "1.0.0" },
    components: {
      securitySchemes: {
        bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" },
      },
    },
  },
  apis: [
    path.join(__dirname, "api", "index.js"),     // ✅ เปลี่ยนเป็น api/index.js
    path.join(__dirname, "routes", "*.js"),
  ],
};

const specs = swaggerJsdoc(options);
module.exports = { swaggerUi, specs };
