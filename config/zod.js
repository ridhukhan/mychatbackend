import {    z  } from "zod"

export const registerSchema =z.object({

fullname: z.string().min(3,"Name atleast 3 char.."),
email: z.string().email("invalid email"),
password: z.string().min(8,"password at least 8 charecter")
    
})

export const loginSchema =z.object({

email: z.string().email("invalid email"),
password: z.string().min(8,"password at least 8 charecter")
    
})