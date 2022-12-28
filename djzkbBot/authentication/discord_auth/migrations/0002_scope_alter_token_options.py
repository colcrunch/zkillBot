# Generated by Django 4.0.8 on 2022-12-25 14:16

from django.db import migrations, models

SCOPES = (
    {
        "name": "activities.read",
        "friendly_name": "Read Activities",
        "help_text": (
            "allows your app to fetch data from a user's \"Now Playing/Recently Played\" list "
            "- requires Discord approval"
        ),
    },
    {
        "name": "activities.write",
        "friendly_name": "Write Activities",
        "help_text": (
            "allows your app to update a user's activity - requires Discord approval "
            "(NOT REQUIRED FOR GAMESDK ACTIVITY MANAGER)"
        ),
    },
    {
        "name": "applications.builds.read",
        "friendly_name": "Read Application Builds",
        "help_text": "allows your app to read build data for a user's application",
    },
    {
        "name": "applications.builds.upload",
        "friendly_name": "Upload Application Builds",
        "help_text": "allows your app to upload/update builds for a user's applications - requires Discord approval",
    },
    {
        "name": "applications.commands",
        "friendly_name": "Application Commands",
        "help_text": "allows your app to use commands in a guild",
    },
    {
        "name": "applications.commands.update",
        "friendly_name": "Update Application Commands",
        "help_text": "allows your app to update its commands using a Bearer token - client credentials grant only",
    },
    {
        "name": "applications.commands.permissions.update",
        "friendly_name": "Update Application Command Permissions",
        "help_text": "allows your app to update permissions for its commands in a guild a user has permissions to",
    },
    {
        "name": "applications.entitlements",
        "friendly_name": "Application Entitlements",
        "help_text": "allows your app to read entitlements for a user's applications",
    },
    {
        "name": "applications.store.update",
        "friendly_name": "Update Application Store",
        "help_text": (
            "allows your app to read and update store data (SKUs, store listings, achievements, etc.) "
            "for a user's applications"
        ),
    },
    {
        "name": "bot",
        "friendly_name": "Bot",
        "help_text": "for oauth2 bots, this puts the bot in the user's selected guild by default",
    },
    {
        "name": "connections",
        "friendly_name": "Connections",
        "help_text": "allows /users/@me/connections to return linked third-party accounts",
    },
    {
        "name": "dm_channels.read",
        "friendly_name": "Read DM Channels",
        "help_text": (
            "allows your app to see information about the user's DMs and group DMs - requires Discord approval"
        ),
    },
    {
        "name": "email",
        "friendly_name": "Email",
        "help_text": "enables /users/@me to return an email",
    },
    {
        "name": "gdm.join",
        "friendly_name": "Join Group DM",
        "help_text": "allows your app to join users to a group dm",
    },
    {
        "name": "guilds",
        "friendly_name": "Guilds",
        "help_text": "allows /users/@me/guilds to return basic information about all of a user's guilds",
    },
    {
        "name": "guilds.join",
        "friendly_name": "Join Guilds",
        "help_text": "allows /guilds/{guild.id}/members/{user.id} to be used for joining users to a guild",
    },
    {
        "name": "guilds.members.read",
        "friendly_name": "Read Guild Members",
        "help_text": "allows /users/@me/guilds/{guild.id}/member to return a user's member information in a guild",
    },
    {
        "name": "identify",
        "friendly_name": "Identify",
        "help_text": "allows /users/@me without email",
    },
    {
        "name": "messages.read",
        "friendly_name": "Read Messages",
        "help_text": (
            "for local rpc server api access, this allows you to read messages from all client channels "
            "(otherwise restricted to channels/guilds your app creates)"
        ),
    },
    {
        "name": "relationships.read",
        "friendly_name": "Read Relationships",
        "help_text": "allows your app to know a user's friends and implicit relationships - requires Discord approval",
    },
    {
        "name": "role_connections.write",
        "friendly_name": "Write Role Connections",
        "help_text": "allows your app to update a user's connection and metadata for the app",
    },
    {
        "name": "rpc",
        "friendly_name": "RPC",
        "help_text": (
            "for local rpc server access, this allows you to control a user's local Discord client"
            " - requires Discord approval"
        ),
    },
    {
        "name": "rpc.activities.write",
        "friendly_name": "Write RPC Activities",
        "help_text": (
            "for local rpc server access, this allows you to update a user's activity - requires Discord approval"
        ),
    },
    {
        "name": "rpc.notifications.read",
        "friendly_name": "Read RPC Notifications",
        "help_text": (
            "for local rpc server access, this allows you to receive notifications pushed out to the user"
            " - requires Discord approval"
        ),
    },
    {
        "name": "rpc.voice.read",
        "friendly_name": "Read RPC Voice",
        "help_text": (
            "for local rpc server access, this allows you to read a user's voice settings"
            " and listen for voice events - requires Discord approval"
        ),
    },
    {
        "name": "rpc.voice.write",
        "friendly_name": "Write RPC Voice",
        "help_text": (
            "for local rpc server access, this allows you to update a"
            " user's voice settings - requires Discord approval"
        ),
    },
    {
        "name": "voice",
        "friendly_name": "Voice",
        "help_text": (
            "for local rpc server access, this allows you to update a user's voice settings - requires Discord approval"
        ),
    },
    {
        "name": "webhook.incoming",
        "friendly_name": "Incoming Webhook",
        "help_text": (
            "this generates a webhook that is returned in the oauth token response for authorization code grants"
        ),
    },
)


def generate_scopes(apps, schema_editor):
    Scope = apps.get_model('discord_auth', 'Scope')
    for s in SCOPES:
        Scope.objects.create(**s)


def delete_scopes(apps, schema_editor):
    Scope = apps.get_model('discord_auth', 'Scope')
    for s in SCOPES:
        try:
            Scope.objects.get(name=s.get('name')).delete()
        except Scope.DoesNotExist:
                pass


class Migration(migrations.Migration):

    dependencies = [
        ('discord_auth', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Scope',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(help_text='The official name of the scope.', max_length=100, unique=True)),
                ('friendly_name', models.CharField(help_text='A user friendly name for the scope.', max_length=150, unique=True)),
                ('help_text', models.TextField(help_text='The official description of the scope.')),
            ],
            options={
                'default_permissions': (),
            },
        ),
        migrations.AlterModelOptions(
            name='token',
            options={'default_permissions': ()},
        ),
        migrations.RunPython(generate_scopes, delete_scopes)
    ]
