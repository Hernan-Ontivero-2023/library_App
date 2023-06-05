class Error{
    message;
    code;
    status;
    data;
    
    constructor(message, code, status, data){
        this.message = message;
        this.code = code;
        this.status = status;
        this.data = data;
    }
}
// message, code, status, data
module.exports = { Error };