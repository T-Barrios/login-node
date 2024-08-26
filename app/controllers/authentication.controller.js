import bcryptjs from "bcryptjs";
import jsonwebtoken from "jsonwebtoken";
import dotenv from "dotenv";

dotenv.config();

export const usuarios = [];

async function login(req, res) {

   const user = req.body.user;
   const password = req.body.password;

    const usuarioARevisar = usuarios.find(usuario => usuario.email === user);
    if (!usuarioARevisar) {
        return res.status(400).send({ status: "Error", message: "Error durante el login" })
          //  console.log(user);
    }
   
 
   const loginCorrecto = await bcryptjs.compare(password, usuarioARevisar.password);
    if (!loginCorrecto) {
        return res.status(400).send({ status: "Error", message: "Error durante el login" })
    }
    const token = jsonwebtoken.sign(
        { user: usuarioARevisar.user },
        process.env.JWT_SECRET,
        { expiresIn: process.env.JWT_EXPIRATION })

    const cookieOption = {
        expires: new Date(Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 60 * 60 * 1000),  //conversion en dias 
        path: "/"
    }
    //Enviar la cookie al cliente
    res.cookie("jwt", token, cookieOption);
    res.send({status: "ok", message: "Usuario loggeado", redirect:"/admin"})
    
}

async function register(req, res) {
  //console.log(req.body);
    const user = req.body.user;
    const password = req.body.password;
    const email = req.body.email;

    //condicionales para verificar si esta vacio o no

    if (!user || !password || !email) {
        return res.status(400).send({status: "Error", message:"Este usuario"})
    }

    const usuarioARevisar = usuarios.find(usuario => usuario.user === user);
    if (usuarioARevisar) {
        return res.status(400).send({status:"Error",message:"Este usuario ya existe"})
    }
    //encriptar el password
    const salt = await bcryptjs.genSalt(5);
    const hashPassword = await bcryptjs.hash(password, salt);
    const nuevoUsuario = {
        user,email,password: hashPassword
    }
    //console.log(nuevoUsuario);
    usuarios.push(nuevoUsuario);

   return res.status(201).send({ status: "ok", message: `Usuario ${nuevoUsuario.user} agregado`, redirect:"/"})
    
}

export const methods = {
    login,
    register
}