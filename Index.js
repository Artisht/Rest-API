const bodyParser = require("body-parser");
const express = require("express");
const app = express();
const server = require("./server.js");
const port = 3000;
const crypto = require("crypto");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.send(`
    <h1>Dokumentation av olika API</h1>
    
    <ul>
    
    <li> GET /Users - returnerar alla användare (Kräver inloggning (TOKEN))</li>

    <li> GET /Users?id=?&Username=?&Country=?&City=? - returnerar alla användare som har matchande parametrar (nycklar), OBS! Alla parametrar behövs inte, du kan skriva dem du vill söka på. (Kräver inloggning (TOKEN))</li>
    
    <li> GET /Users:id - returnerar användare med angivet id (Kräver inloggning (TOKEN)) </li>
    
    <li>POST /RegisterUser - skapa ett konto</li>
    
    <li>POST /loggin - logga in på ditt konto </li>
    
    </ul>`);
});

function hash(data) {
  const hash = crypto.createHash("sha256");
  hash.update(data);
  return hash.digest("hex");
}

app.get("/Users", async (req, res) => {
  let Validation = server.AuthorizeUser(req, res, SECRETHASH);
  if (Validation != false) {
    if (Object.keys(req.query).length > 0) {
      let id = req.query.id || null;
      let Username = req.query.Username || null;
      let Country = req.query.Country || null;
      let City = req.query.Country || null;
      let result = await server.GetUniqueUser(id, Username, Country, City);
      res.send(result);
    } else {
      let result = await server.GetUsers();
      res.send(result);
    }
  }
});

app.get("/Users/:id", async (req, res) => {
  let Validation = server.AuthorizeUser(req, res, SECRETHASH);
  if (Validation != false) {
    let id = req.params.id;
    let result = await server.GetUniqueUser(id, null, null, null);
    res.send(result);
  }
});

function ValidateUser(body) {
  return body && body.Username;
}

app.post("/RegisterUser", async (req, res) => {
  if (ValidateUser(req.body)) {
    let Username = req.body.Username;
    let Country = req.body.Country;
    let City = req.body.City;
    let id = req.body.id;
    let HashedPassword = hash(req.body.Password);

    let check = await server.GetUser(Username);
    if (check.length < 1) {
      let ins = await server.AddUser(Username, HashedPassword, Country, City);

      let result = {
        Username: Username,
        Country: Country,
        City: City,
        id: id,
      };
      res.json(result);
    } else {
        Message = "Username Taken"
        res.status(400).send(Message);
    }
  } else {
    res.sendStatus(422);
  }
});

app.put("/Users/:id", async (req, res) => {
  if (ValidateUser(req.body)) {
    let id = req.params.id;
    let IsValidId = await server.GetUniqueUser(id);
    if (IsValidId.length > 0) {
      let Username = req.body.Username;
      let HashedPassword = hash(req.body.Password);
      let Country = req.body.Country;
      let City = req.body.City;

      let UpdateUser = await server.UpdateUser(
        Username,
        HashedPassword,
        Country,
        City,
        id
      );

      let result = {
        Username: Username,
        Country: Country,
        City: City,
        id: id,
      };
      res.json(result);
    } else {
      res.sendStatus(422);
    }
  } else {
    res.sendStatus(422);
  }
});

var jwt = require("jsonwebtoken");
const SECRET = "Hassan abood phon is grape";
const SECRETHASH = hash(SECRET);

app.post("/Login", async (req, res) => {
  let Username = req.body.Username;
  let HashedPassword = hash(req.body.Password);
  let User = await server.GetUser(Username);
  if (HashedPassword === User.Password) {
    let payload = {
      sub: User.id,
      username: Username,
      Country: User.Country || null,
      City: User.City || null,
      expiresIn: "1h",
    };
    let token = jwt.sign(payload, SECRETHASH);
    res.json(token);
  } else {
    res.sendStatus(401);
  }
});

app.listen(port, () => {
  console.log(`Lisining on port ${port}`);
});
