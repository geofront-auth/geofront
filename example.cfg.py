# This is a configuration example.  See docs/config.rst as well.

# Scenario: Your team is using GitHub, and the organization login is @YOUR_TEAM.
# All members already registered their public keys to their GitHub accounts,
# and are using git through ssh public key authorization.

# First of all, you have to decide how to authorize team members.
# Geofront provides a built-in authorization method for GitHub organizations.
# It requires a pair of client keys (id and secret) for OAuth authentication.
# You can create one from:
#
# https://github.com/organizations/YOUR_TEAM/settings/applications/new
#
# Then import GitHubOrganization class, and configure a pair of client keys
# and your organization login name (@YOUR_TEAM in here).
from geofront.backends.github import GitHubOrganization

TEAM = GitHubOrganization(
   client_id='0123456789abcdef0123',
   client_secret='0123456789abcdef0123456789abcdef01234567',
   org_login='YOUR_TEAM'
)

# Your colleagues have already registered their public keys to GitHub,
# so you don't need additional storage for public keys.  We'd use GitHub
# as your public key store.
from geofront.backends.github import GitHubKeyStore

KEY_STORE = GitHubKeyStore()

# Unlike public keys, the master key ideally ought to be accessible by
# only Geofront.  Assume you use Amazon Web Services.  So you'll store
# the master key to the your private S3 bucket named your_team_master_key.
from geofront.backends.cloud import CloudMasterKeyStore
from libcloud.storage.types import Provider
from libcloud.storage.providers import get_driver

driver_cls = get_driver(Provider.S3)
driver = driver_cls('aws access key', 'aws secret key')
container = driver.get_container(container_name='your_team_master_key')
MASTER_KEY_STORE = CloudMasterKeyStore(driver, container, 'id_rsa')

# You have to let Geofront know what to manage remote servers.
# Although the list can be hard-coded in the configuration file,
# but you'll get the list dynamically from EC2 API.  Assume our all
# AMIs are Amazon Linux, so the usernames are always ec2-user.
# If you're using Ubuntu AMIs it should be ubuntu instead.
from geofront.backends.cloud import CloudRemoteSet
from libcloud.compute.types import Provider
from libcloud.compute.providers import get_driver

driver_cls = get_driver(Provider.EC2)
driver = driver_cls('aws access id', 'aws secret key', region='uest-east-1')
REMOTE_SET = CloudRemoteSet(driver, user='ec2-user')

# Suppose your team is divided by several subgroups, and these subgroups are
# represented in teams of the GitHub organization.  So you can control
# who can access each remote by specifying allowed groups to its metadata.
# CloudRemoteSet which is used for above REMOTE_SET exposes each EC2 instance's
# metadata as it has.  We suppose every EC2 instance has Allowed-Groups
# metadata key and its value is space-separated list of group slugs.
# The following settings will allow only members who belong to corresponding
# groups to access.
from geofront.remote import GroupMetadataPermissionPolicy

PERMISSION_POLICY = GroupMetadataPermissionPolicy('Allowed-Groups')

# Geofront provisions access tokens (or you can think them as sessions)
# for Geofront clients.  Assume you already have a Redis server running
# on the same host.  We'd store tokens to the db 0 on that Redis server
# in the example.
from werkzeug.contrib.cache import RedisCache

TOKEN_STORE = RedisCache(host='localhost', db=0)
