class appError extends Error {
  constructor(message,statusCode){
      super(message)
      this.statusCode = statusCode 
      this.status = `${statusCode}`.startsWith("4")? "fail":"error"
      // to check if i know the error and handle
      this.isOperational = true 
      
      Error.captureStackTrace(this,this.constructor)
  }
}

module.exports = appError

