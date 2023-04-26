const mysql = require("mysql2/promise");

async function GetConnection() {
  return mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "",
    database: "rest-api",
  });
}

async function GetUsers() {
  const con = await GetConnection();
  const result = await con.execute("SELECT * FROM users");
  await con.end();
  return result[0];
}

async function GetUniqueUser(id, Username, Country, City) {
  const con = await GetConnection();
  const result = await con.execute(
    "SELECT * FROM users WHERE id = ? or Username = ? or Country = ? or City = ?",
    [id, Username, Country, City]
  );
  await con.end();
  return result[0];
}

async function AddUser(Username, Password, Country, City) {
  const con = await GetConnection();
  const result = await con.execute(
    "INSERT users(Username, Password, Country, City) VALUES(?, ?, ?, ?)",
    [Username, Password, Country, City]
  );
  await con.end();
  return result[0];
}

async function UpdateUser(Username, Password, Country, City, id) {
  const con = await GetConnection();
  const result = await con.execute(
    "UPDATE users SET Username = ?, Password = ?, Country = ?, City = ? WHERE id = ?",
    [Username, Password, Country, City, id]
  );
  await con.end();
  return result[0];
}

async function GetUser(Username) {
  const con = await GetConnection();
  const result = await con.execute("SELECT * FROM users WHERE Username = ?", [
    Username,
  ]);
  await con.end();
  return result[0];
}

var jwt = require("jsonwebtoken");

async function AuthorizeUser(req, res, SECRETHASH) {
  let AuthHeader = req.headers["authorization"];
  if (AuthHeader === undefined) {
    res.status(401).send("Unauthorized");
    console.log("Yes")
    return false;
  }
  let token = AuthHeader.slice(7);

  let verify;
  try {
    verify = jwt.verify(token, SECRETHASH);
  } catch (err) {
    console.log(err);
    res.status(401).send("Invalid auth token");
    return false;
  }
  console.log(verify)
  return verify;
}

module.exports = {
  GetUsers,
  GetUniqueUser,
  AddUser,
  UpdateUser,
  GetUser,
  AuthorizeUser,
};
