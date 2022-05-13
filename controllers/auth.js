const { Router, response } = require('express');
const { validationResult } = require('express-validator');
const bcrypt = require('bcryptjs');

const Usuario = require('../models/usuario');
const {generarJWT} = require('../helpers/jwt');


const crearUsuario = async (req, res = response) => {

    const {email, password} = req.body;

    try {

        const existeEmail = await Usuario.findOne({email});
        if(existeEmail){
            return res.status(400).json({
                ok: false,
                msg: 'El correo ya existe'
            });
        }

        const usuario = new Usuario( req.body );

        // Exriptar contraseñas
        const salt = await bcrypt.genSaltSync();
        usuario.password = await bcrypt.hashSync(password, salt);

        await usuario.save();

        // Generar JWT
        const token = await generarJWT(usuario.id);

        res.json({
            ok: true,
            usuario,
            token
        });
    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hubo un error en el registrar'
        });   
    } 
}

const login = async (req, res = response) => {

    const {email, password} = req.body;

    try {

        const usurioDB = await Usuario.findOne({email});

        if(!usurioDB){
            return res.status(400).json({
                ok: false,
                msg: 'El correo no existe'
            });
        }

        // Validar Password
        const validPassword = bcrypt.compareSync(password, usurioDB.password);
        if(!validPassword){
            return res.status(400).json({
                ok: false,
                msg: 'El password es incorrecto'
            });
        }

        // Generar JWT
        const token = await generarJWT(usurioDB.id);

        res.json({
            ok: true,
            usuario: usurioDB,
            token
        });


    } catch (error) {
        console.log(error);
        res.status(500).json({
            ok: false,
            msg: 'Hubo un error en el login'
        });   
    } 
}

const renewToken = async (req, res = response) => {
    const uid = req.uid;
    console.log(uid, 'holaaaaa');

    const token = await generarJWT(uid);

    const usuario = await Usuario.findById(uid);

    res.json({
        ok: true,
        usuario,
        token
    });

}

module.exports = {
    crearUsuario,
    login,
    renewToken
}