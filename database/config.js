const mongoose = require('mongoose');

const dbConnection = async() => {
    try{
        await mongoose.connect(process.env.DB_CNN, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            // useCreateIndex: true
        });
        console.log('DB online');
    }catch(err){
        console.log(err);
        throw  new Error('Erro en la BD');
    }
}

module.exports = {
    dbConnection
}