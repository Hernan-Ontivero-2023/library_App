const consoleLoggingMIDWW = (req, res, next) => {
    console.log(`Req method: ${req.method}, req url: ${req.url}`);
    console.log(`authorization:  ${req.get('authorization')}`);
    next();
}


module.exports = consoleLoggingMIDWW;