const catchAsync =  (fn) => {
  return (req, res, next) => {
    fn(req, res, next).catch(next);
  };
};

const appError = require("./appError")
const sendEmail = require("./sendEmail")
const jwt = require("jsonwebtoken")
const crypto = require("crypto")
const bcrypt = require("bcrypt")
const { promisify } = require("util")

let User;

exports.setUserModel = (model) => {
  User = model;
}
const createToken = async (id, expiresIn) => {
  return await jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn });
};

const createAndSendToken = async (user, auth, statusCode, res) => {
  const refreshToken = await createToken(auth.user_id, '30d');

  res.cookie("refreshToken", refreshToken, { httpOnly: true, maxAge: 30 * 24 * 60 * 60 * 1000 });
  auth.refreshToken = refreshToken;
  auth.save();

  const accessToken = await createToken(auth.user_id, '5m');
  let userResponse = {
    id: user.id,
    user_name: user.user_name,
    email: user.email,
    user_role: user.user_role,
    phone_number: user.phone_number,
    address_id: user.address_id,
  };

  res.status(statusCode).json({
    status: "success",
    data: {
      user: userResponse,
      accessToken,
    },
  });
};



// the idea of creating verificationToken and passwordResetToken is take them from request and hash them and compare with one stored in database
// there is two way of creating token (create random string, create jwt -> more secure)
// in email verefication we use jwt in password we use random string  
exports.signUp = () => {
  return catchAsync(async (req, res, next) => {
    // const { name, password, passwordConfirm, email, birthdate, profilePic, cover } = req.body
    
    const user = await User.create(req.body)
    const verificationToken = await user.createTokenForValidation()
    await user.save({ validateBeforeSave: false })
    try {
      sendEmail({ email: user.email, subject: `verify your email (for 10 minutes)`, token: verificationToken })
      res.status(200).json({
        status: `success`,
        message: `token send to email`
      })
    } catch (err) {
      user.verificationToken = null
      await user.save({ validateBeforeSave: false })
      return next(new appError("there was an error sending the email , try again", 500))
    }
  })
}

// in passowrdResetToken we create token fron crypto but here we create token using jwt and put email init 
// exports.verify
exports.verify = () => {
  return catchAsync(async (req, res, next) => {
    let token = req.params.token;
    token = crypto.createHash("sha256")
      .update(token)
      .digest('hex');
    const user = await User.findOne({ verificationToken: token });

    if (!user) {
      return next(new appError("There is no user with this email", 403));
    }

    user.isVerified = true;
    await user.save({ validateBeforeSave: false });

    createAndSendToken(user, 200, res);
  });
}


exports.sendVerivicationEmail = () => {
  return catchAsync(async (req, res, next) => {
    const user = await User.findOne({ email })
    const verificationToken = await user.createTokenForValidation()
    await user.save({ validateBeforeSave: true })
    try {
      await sendEmail({ email: user.email, subject: `verify your email (for 10 minutes)`, token: verificationToken })
      res.status(200).json({
        status: `success`,
        message: `token send to email`
      })
    } catch (error) {
      user.verificationToken = null
      await user.save({ validateBeforeSave: false })
      return next(new appError("there was an error sending the email , try again", 500))
    }
  })
}

exports.login = () => {
  return catchAsync(async (req, res, next) => {
    const { email, password } = req.body
    if (!email || !password) {
      return next(new appError("should input email and password"))
    }
    const user = await User.findOne({ email })
    if (!user) {
      return next(new appError("There is no user with this email"))
    }
    const isPasswordMatch = await bcrypt.compare(password, user.password)

    if (!isPasswordMatch) {
      return next(new appError("Wrong password"))
    }
    createAndSendToken(user, 200, res)
  })
}

exports.logout = () => {
  return catchAsync(async (req, res, next) => {
    if (!req.cookies?.refreshToken) {
      return next(new appError("there is no token in the cookie", 404))
    }
    const user = await User.findOne({ refreshToken: req.cookies.refreshToken })
    if (user) {
      return next(new appError("Cant find user!",404))
    }
    
    await User.findByIdAndUpdate(user._id, { refreshToken: "" })
    res.clearCookie("refreshToken")
    res.status(200).json({
      status: "success",
      message: "Logged out successfully",
    })
  })
}

exports.protect = () => {
  return catchAsync(async (req, res, next) => {
    let token = req.headers?.authorization;

    if (!token || !token.startsWith("Bearer")) {
      return next(new appError("No token in Bearer auth!", 401));
    }
  
    token = token.split(" ")[1];
    if (!req.cookies.refreshToken) {
      return next(new appError("No refreshToken in cookie!", 401));
    }
  
    if (!req.cookies.refreshToken) {
      return next(new appError("No refreshToken found in cookie", 400))
    }

    try {
      var decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET); /*extract data*/
    } catch (err) {
      return next(new appError("invalid token"))
    }
    const user = await User.findById(decoded.id)
    if (!user) {
      return next(new appError("there isno user", 404))
    }
    if (!user.isVerified) {
      return next(new appError("this email dont verify registeration"))
    }
    if (!user.refreshToken) {
      return next(new appError("must be logged in", 400))
    }

    req.user = user
    next()
  })
}

exports.refreshToken = () => {
  return catchAsync(async (req, res, next) => {
    let refreshToken = req.cookies?.refreshToken;

    if (!refreshToken) {
      return next(new appError("No refreshToken found in cookie", 400));
    }
    const user = await User.findOne({ refreshToken })
    if (!user) {
      return next(new appError("there is no user with this token", 404))
    }
    try {
      // The purpose of this verification is to ensure that the refresh token is valid and has not been tampered with.     
      await promisify(jwt.verify)(user?.refreshToken, process.env.JWT_SECRET)
    } catch (err) {
      return next(new appError("invalid token", 400))
    }
    const accessToken = await createToken(user._id,"5m")
    res.status(200).json({ accessToken })
  })
}

exports.forgotPassword = () => {
  return catchAsync(async (req, res, next) => {
    const email = req.body.email
    if (!email) {
      return next(new appError("there is no email with request", 404))
    }
    const user = await User.findOne({ email })
    if (!user) {
      return next(new appError("there is no user with this email", 404))
    }
    const resetToken = await user.createPasswordResetToken()
    await user.save({ validateBeforeSave: false })
    try {
      await sendEmail({ email: user.email, subject: `reset your passowrd (for 10 minutes)`, token: resetToken })
    }
    catch (err) {
      return next(new appError("error in sending email", 404))
    }
    res.status(200).json({
      status: `success`,
      message: `token send to email`
    })
  })
}

exports.resetPassword = () => {
  return catchAsync(async (req, res, next) => {
    const resetToken = req.params.token
    if (!resetToken) {
      return next(new appError("there is no token in requset", 404))
    }
    const hashedToken = crypto.createHash('sha256')
      .update(resetToken)
      .digest('hex');

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() }
    })
    // 2) If token has not expired, and there is user, set the new password
    if (!user) {
      return next(new appError('Token is invalid or has expired', 400));
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: true })

    const token = await createToken(user._id)
    res.json({ status: "success", data: { user }, token })
  })
}

exports.updatePassword = () => {
  return catchAsync(async (req, res, next) => {
    const user = req.user
    const isPasswordMatch = await bcrypt.compare(req.body.currentPassword, user.password)
    if (!isPasswordMatch) {
      return next(new appError("Wrong password"))
    }
    user.password = req.body.password
    user.passwordConfirm = req.body.passwordConfirm
    await user.save()

    const token = await createToken(user._id)
    res.json({ status: "success", data: { user }, token })
  })
}