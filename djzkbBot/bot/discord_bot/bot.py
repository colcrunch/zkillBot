from datetime import datetime
from logging import getLogger

import discord
from discord.ext.commands import Bot

from django.conf import settings


class ZKillBot(Bot):
    def __init__(self, *args, **kwargs):
        #   TODO: Implement an *actual* bot. lol
        intents = discord.Intents.all()

        self.description = "A discord.py bot to track eve online kills."

        self.token = settings.DISCORD_BOT_TOKEN
        self.prefix = "!"
        self.started = datetime.now()

        self.logger = getLogger(__name__)

        super().__init__(
            command_prefix=self.prefix,
            description=self.description,
            pm_help=None,
            activity=discord.Activity(name="10101010", type=discord.ActivityType.playing),
            status=discord.Status.idle,
            intents=intents,
            *args,
            **kwargs
        )

    def run(self):
        super().run(self.token)

    async def on_ready(self):
        print("Bot Started!")
        self.logger.info(f"Bot Started! (U: {self.user.name} I: {self.user.id})")

