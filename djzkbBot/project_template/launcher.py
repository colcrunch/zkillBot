from djzkbBot.bot.discord_bot.bot import ZKillBot
import os


os.environ.setdefault("DJANGO_SETTINGS_MODULE", "{{ project_name}}.settings.local")
bot = ZKillBot()
ZKillBot.run(bot)
