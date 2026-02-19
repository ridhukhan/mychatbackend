import { Conversation } from "../models/conversation.js";
import { Message } from "../models/message.js";
import { getReceiverSocketId, io } from "../Socket/Socket.js";

export const sendMessage =  async(req,res)=>{

try {
    const {message}=req.body;
    const {id:receiverId}=req.params;
    const senderId=req.user._id;

     if (!message) {
      return res.status(400).json({
        error: "message required",
      });
    }

    let conversation=await Conversation.findOne({
        members:{$all:[senderId,receiverId]}
  })
        if(!conversation){
            conversation=await Conversation.create({
                members:[senderId,receiverId]
            })
        }
  const newMessage= new Message({
    senderId,
    receiverId,
    message,
  })
  if(newMessage){
    conversation.message.push(newMessage._id)
  }

  await Promise.all([conversation.save(),newMessage.save()])

const receiverSocketId =getReceiverSocketId(receiverId);
if(receiverSocketId){
  io.to(receiverSocketId).emit("newMessage",newMessage)
}

  res.status(200).json(newMessage)
} catch (error) {
    console.log(error.message)
    res.status(500).json({error:"INTERNAL SERVER ERROR"})
}


}
export const getMessage =async(req,res)=>{
try {
    const {id:userToChatId}=req.params;

    const senderId=req.user._id;
    const conversation = await Conversation.findOne({
        members:{$all:[senderId,userToChatId]}
    }).populate("message")
    if(!conversation){
       return res.status(200).json([])
    }
const messages= conversation.message
res.status(200).json(messages)
} catch (error) {
    console.log("error in get mesages",error.message)
}


}
