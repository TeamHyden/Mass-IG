import subprocess
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    user_id = update.message.from_user.id
    await update.message.reply_text("Hello! Welcome to the bot.")
    
    with open('id.txt', 'w') as file:
        file.write(f"{user_id}\n")

async def accounter(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    await update.message.reply_text("Script has been Started!!!")
    subprocess.run(["python", "ig.py"])

def main():
    
    tg_bot_token = " " # insert the telegram bot token  inside here 

    application = ApplicationBuilder().token(tg_bot_token).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("Scrap", accounter))

    application.run_polling()

if __name__ == '__main__':
    main()
