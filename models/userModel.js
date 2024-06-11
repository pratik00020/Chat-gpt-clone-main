const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const JWT = require("jsonwebtoken");
const cookie = require("cookie");

//models
const userSchema = new mongoose.Schema({ // database scheme of mongoose
  username: { // different types of data
    type: String,
    required: [true, "USername is Required"],
  },
  email: {
    type: String,
    required: [true, "Email is required"],
    unique: true,
  },
  password: {
    type: String,
    required: [true, "Password is required"],
    minlength: [6, "Password length should be 6 character long"],
  },
  customerId: {
    type: String,
    default: "",
  },
  subscription: {
    type: String,
    default: "",
  },
});

//hashed password - crypting the password using the bycrpt js library
userSchema.pre("save", async function (next) {
  //update
  if (!this.isModified("password")) {
    next();
  }
  const salt = await bcrypt.genSalt(10); // salt = could be called hashing variable to be used with password
  this.password = await bcrypt.hash(this.password, salt); // hash the password and salt
  next();
});

//match password
userSchema.methods.matchPassword = async function (password) {
  return await bcrypt.compare(password, this.password); // checking the pass by inbuilt bycrpt func .compare
};

//SIGN TOKEN
userSchema.methods.getSignedToken = function (res) { // generation of token
  const acccesToken = JWT.sign( // creating access token using JWT.sing func
    { id: this._id}, // making access token using three parameters 1. id
    process.env.JWT_ACCESS_SECRET, // access token made in .env file 
    { expiresIn: "1h"} // time period of expire
  );
  const refreshToken = JWT.sign( //same with refresh token
    { id: this._id },
    process.env.JWT_REFRESH_TOKEN,
    { expiresIn: "15 days"}
  );
  res.cookie("refreshToken", `${refreshToken}`, { // creation of cookie
    maxAge: 86400 * 7000,
    httpOnly: true,
  });
};

const User = mongoose.model("User", userSchema); //initializing all the database into user and exporting it.

module.exports = User;