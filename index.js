const express = require("express");
const app = express();
const port = 3000;


app.get("/", (req, res) => {
  res.send("Backend runing...");
});

//User management API
app.get("/Users", (req, res) => {
  res.send("Get Users All");
});

app.post("/Users", (req, res) => {
  res.send("Post Users");
});

app.put("/Users", (req, res) => {
  res.send("Put Users");
});

app.delete("/Users", (req, res) => {
  res.send("Delete Users");
});

app.get('/users/:id', (req, res) => {
  res.send(req.params)
})

//Product management API
app.get("/Users", (req, res) => {
  res.send("Get products All");
});

app.post("/Users", (req, res) => {
  res.send("Post products");
});

app.put("/Users", (req, res) => {
  res.send("Put products");
});

app.delete("/Users", (req, res) => {
  res.send("Delete products");
});

app.listen(port, () => {
  console.log(`Example app listening on port http://localhost:${port}`);
});
