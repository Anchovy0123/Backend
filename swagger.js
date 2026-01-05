const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");
const path = require("path");

// swagger-jsdoc จะอ่านคอมเมนต์ @openapi จากไฟล์ที่กำหนดใน apis
const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "BackEnd API",
      version: "1.0.0",
    },
    // ให้ Swagger UI มีปุ่ม Authorize (Bearer token)
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
        },
      },
    },
  },
  apis: [
    path.join(__dirname, "index.js"),
    path.join(__dirname, "routes", "*.js"),
  ],
};

const specs = swaggerJsdoc(options);

module.exports = { swaggerUi, specs };
