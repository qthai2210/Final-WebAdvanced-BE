import * as Joi from 'joi';

export const validationSchema = Joi.object({
  PORT: Joi.number().default(4000),
  MONGO_DATABASE_URI: Joi.string().required(),
  //JWT_SECRET: Joi.string().required(),
  //JWT_EXPIRES_IN: Joi.string().default('1d'),
  RABBITMQ_URL: Joi.string().required(),
  RABBITMQ_QUEUE: Joi.string().required(),
});
