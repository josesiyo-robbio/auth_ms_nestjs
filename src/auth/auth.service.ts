


import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { LoginUserDto, RegisterUserDto } from './dto';
import { RpcException } from '@nestjs/microservices';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { JwtPayloadInterface } from './interfaces/jwt-payload.interfcae';
import { envs } from 'src/config';



@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit 
{

    constructor(private readonly jwtService : JwtService)
    {
        super();
    }


    private readonly logger = new Logger('AUTHSERVICE');

    onModuleInit() 
    {
        this.$connect();
        this.logger.log('MONGO DB CONNECTED');
    }


    async signJWT(payload : JwtPayloadInterface)
    {
        const jwtSigned = this.jwtService.sign(payload);
        return jwtSigned;
    }


    async verifyToken(token:string)
    {
        try
        {
            const {sub,iat, exp, ...user} = this.jwtService.verify(token, { secret : envs.jwtSecret });
            return {
                user    :   user,
                token   :   await this.signJWT(user)
            }
        }
        catch(error)
        {
            throw new RpcException({
                status  :   401,
                message :   'invalid token'
            })
        }
    }


    async registerUser(registerUserDto: RegisterUserDto) 
    {
        const { email, name, password } = registerUserDto;

        try 
        {
            const user = await this.user.findUnique(    {where : { email }   })

            if(user)
            {
                throw new RpcException({
                    status  : 400,
                    message : 'user alreadey exist'
                })
            }

            const newUser = await this.user.create({
                data : {
                    email,
                    password : bcrypt.hashSync(password,10),
                    name
                }
            });

            const {password : __, ...rest } = newUser;

            return {
                user    :   rest,
                token   :   await this.signJWT(rest)
            }
        }
        catch (error)
        {
            throw new RpcException({
                status : 400,
                message : error.message
            })
        }
    }


    async loginUser(loginUserDto: LoginUserDto) 
    {
        const { email, password } = loginUserDto;

        try 
        {
            const user = await this.user.findUnique({   where : { email }   })

            if(!user)
            {
                throw new RpcException({
                    status  :   400,
                    message :   'User/Password not valid'
                })
            }

            const isPasswordValid = bcrypt.compareSync(password,user.password);

            if(!isPasswordValid)
            {
                throw new RpcException({
                    status  :   400,
                    message :   'User/Password not valid'
                })
            }

            const {password : __, ...rest } = user;

            return {
                user    :   rest,
                token   :   await this.signJWT(rest)
            }
        }
        catch (error)
        {
            throw new RpcException({
                status : 400,
                message : error.message
            })
        }
    }

}
