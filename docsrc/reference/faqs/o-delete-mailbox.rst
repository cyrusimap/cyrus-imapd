Why can I not delete a mailbox as an admin user?
------------------------------------------------

By default, the permissions on newly created mailboxes do not allow 
access to any other user. Therefore even root user can not delete 
mailbox. 

To delete a mailbox, you need to give appropriate rights with the 
command ``sam user.mailbox username all`` after that you can delete the 
mailbox. Even just giving the user the "c" right (Create and Delete 
mailbox) is enough. 


