import os
from azure.common.credentials import ServicePrincipalCredentials
# from azure.mgmt.authorization import AuthorizationManagementClient
# from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.msi import ManagedServiceIdentityClient
# from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient

# from azure.common.client_factory import get_client_from_cli_profile

# Variable name for template dir
from msrestazure.azure_exceptions import CloudError

template_dir = 'templates'
datalake_dir = 'datalakes'
LOCATION = 'westus'


class AzureFactory:
    datalakename = None
    subscription_id = None
    resource_group = None
    credentials = None

    resource_client = None
    compute_client = None
    network_client = None
    authorization_client = None
    msi_client = None

    resource_group_exists = False

    def __init__(self):
        if os.environ.get('AZURE_SUBSCRIPTION_ID') is not None:
            self.subscription_id = os.environ.get('AZURE_SUBSCRIPTION_ID')  # your Azure Subscription Id
        else:
            raise ValueError('AZURE_SUBSCRIPTION_ID environment variable missing')

        # Sanity check
        if os.environ.get('AZURE_CLIENT_ID') is None:
            raise ValueError('AZURE_CLIENT_ID environment variable missing')
        if os.environ.get('AZURE_CLIENT_SECRET') is None:
            raise ValueError('AZURE_CLIENT_SECRET environment variable missing')
        if os.environ.get('AZURE_TENANT_ID') is None:
            raise ValueError('AZURE_TENANT_ID environment variable missing')

        self.credentials = ServicePrincipalCredentials(
            client_id=os.environ['AZURE_CLIENT_ID'],
            secret=os.environ['AZURE_CLIENT_SECRET'],
            tenant=os.environ['AZURE_TENANT_ID']
        )

        self.resource_client = ResourceManagementClient(self.credentials, self.subscription_id)
        # self.compute_client = ComputeManagementClient(self.credentials, self.subscription_id)
        # self.network_client = NetworkManagementClient(self.credentials, self.subscription_id)
        # self.authorization_client = AuthorizationManagementClient(self.credentials, self.subscription_id)
        self.msi_client = ManagedServiceIdentityClient(self.credentials, self.subscription_id)

    def vendor(self):
        return "Microsoft"

    def build(self, ddf):
        datalakename = ddf['datalake']
        storage = dict()
        for name, path in ddf['storage'].items():
            # build dictionary for storage locations
            storage[name] = path['path']
        print('Building ' + self.vendor() + ' Cloud artifacts for datalake named: ' + datalakename + '...')
        # print(storage)

        for name, role in ddf['datalake_roles'].items():
            # Read instance profile as MSIs
            msi = False
            if "instance_profile" in role:
                msi = role['instance_profile']
            if "msi" in role:
                msi = role['msi']

            permissions = role['permissions']
            i = 0
            for perm in permissions:
                # print(perm)
                elements = perm.split(':')
                if elements[0] == 'storage':
                    perm_name = elements[1]
                    filepath = template_dir + '/azure/' + perm_name + '.json'
                    if os.path.exists(filepath):
                        from string import Template
                        # open template file
                        d = storage
                        d['storage_location'] = storage[elements[2]]
                        d['subscription_id'] = os.getenv('AZURE_SUBSCRIPTION_ID', 'MY_AZURE_SUBSCRIPTION_ID')
                        with open(filepath, 'r') as reader:
                            t = Template(reader.read())
                            t = t.safe_substitute(d)

                        filename = datalake_dir + '/' + datalakename + '/Azure/' + role['iam_role'] + '-policy.json'
                        suffix = ''
                        if os.path.exists(filename):
                            suffix = str(i)
                        # open output file
                        with open(
                                datalake_dir + '/' + datalakename + '/Azure/' + role[
                                    'iam_role'] + '-policy' + suffix + '.json',
                                'w') as writer:
                            writer.write(t)
                        print('The datalake role: ' + name + ' is assigned the iam role: ' +
                              role['iam_role'] + ' which has been granted: ' + perm_name +
                              ' for path: ' + d['storage_location'])
                    else:
                        print('Unknown permissions element: ' + elements[1] + ' check permissions in ddf file')
                elif elements[0] == 'sts':
                    filepath = template_dir + '/azure/assume-roles.json'
                    if os.path.exists(filepath):
                        from string import Template
                        # open template file
                        d = dict()
                        d['subscription_id'] = os.getenv('AZURE_SUBSCRIPTION_ID', 'MY_AZURE_SUBSCRIPTION_ID')
                        with open(filepath, 'r') as reader:
                            t = Template(reader.read())
                            t = t.safe_substitute(d)
                        filename = datalake_dir + '/' + datalakename + '/Azure/' + role['iam_role'] + '-policy.json'
                        suffix = ''
                        if os.path.exists(filename):
                            suffix = '-' + str(i)
                        # open output file
                        with open(
                                datalake_dir + '/' + datalakename + '/Azure/' + role[
                                    'iam_role'] + '-policy' + suffix + '.json',
                                'w') as writer:
                            writer.write(t)
                        print('The datalake role: ' + name + ' is assigned the iam role: ' +
                              role['iam_role'] + ' which has been granted: assumeRoles')
                # elif elements[0] == 'db':

                i = i + 1

    def push(self, ddf):
        self.create_identities(ddf)

    def create_identities(self, ddf):
        self.datalakename = ddf['datalake']
        # create IDB role
        idbrole = ddf['datalake_roles']['IDBROKER_ROLE']
        self.create_MSI(idbrole['iam_role'])

        # Create other roles
        for name, role in ddf['datalake_roles'].items():
            role_name = role['iam_role']
            if name != 'IDBROKER_ROLE':
                self.create_MSI(role_name)

    def create_MSI(self, identity):
        self.resource_group = os.environ.get('AZURE_RESOURCE_GROUP',
                                             self.datalakename + 'RG')  # your Azure resource group
        # Create a RG if not already.
        self.create_resource_group()

        try:
            if self.msi_client.user_assigned_identities.get(self.resource_group,
                                                            identity,  # Any name, just a human readable ID
                                                            custom_headers=None):
                print(f"identity {identity} already exists")
        except CloudError:
            idb_identity = self.msi_client.user_assigned_identities.create_or_update(
                self.resource_group,
                identity,  # Any name, just a human readable ID
                LOCATION
            )
            print(
                f"Created MSI {idb_identity.id} for Datalake {self.datalakename} in resource group {self.resource_group}")


    def create_resource_group(self):
        self.resource_group = os.environ.get('AZURE_RESOURCE_GROUP',
                                             self.datalakename + 'RG')  # your Azure resource group

        # If RG exist don't create one
        # Checking for RG can be expensive, check for local cache
        if self.resource_group_exists:
            return

        # Check if RG exists in Azure
        for rg in self.resource_client.resource_groups.list():
            if rg.name == self.resource_group:
                self.resource_group_exists = True
                print(f"Resource group {self.resource_group} already exists.")
                return

        # Provision the resource group.
        rg_result = self.resource_client.resource_groups.create_or_update(
            self.resource_group,
            {
                "location": LOCATION
            }
        )
        print(f"Provisioned resource group {rg_result.name} in the {rg_result.location} region")

    # Delete RG - proceed with caution.
    def delete_resource_group(self):
        self.resource_client.resource_groups.delete(self.resource_group)

    def __str__(self):
        return "Azure"
