const swaggerJsdoc = require("swagger-jsdoc");
const swaggerUi = require("swagger-ui-express");

const path = require("path");

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "BackEnd API",
      version: "1.0.0",
    },
  },
  apis: [path.join(__dirname, "/routes/*.js")], // path ไฟล์ที่มี comment swagger
};

const specs = swaggerJsdoc(options);

module.exports = { swaggerUi, specs };
