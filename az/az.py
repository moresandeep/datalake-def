import json
import os
import uuid

from azure.common.credentials import ServicePrincipalCredentials
from azure.identity import ClientSecretCredential
from azure.mgmt.msi import ManagedServiceIdentityClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.resource.policy import PolicyClient
from azure.mgmt.authorization import AuthorizationManagementClient
from azure.mgmt.authorization.models import (Permission, RoleDefinitionProperties)
from azure.mgmt.storage import StorageManagementClient
from azure.storage.filedatalake import DataLakeServiceClient

# Variable name for template dir
from msrest.serialization import Model
from msrestazure.azure_exceptions import CloudError

template_dir = 'templates'
datalake_dir = 'datalakes'
LOCATION = 'westus'


class CustomRoleDefinition(Model):
    """ Role definition Model """

    _validation = {
    }

    _attribute_map = {
        'id': {'key': 'id', 'type': 'str'},
        'name': {'key': 'name', 'type': 'str'},
        'type': {'key': 'type', 'type': 'str'},
        'role_name': {'key': 'properties.roleName', 'type': 'str'},
        'description': {'key': 'properties.description', 'type': 'str'},
        'role_type': {'key': 'properties.type', 'type': 'str'},
        'permissions': {'key': 'properties.permissions', 'type': '[Permission]'},
        'assignable_scopes': {'key': 'properties.assignableScopes', 'type': '[str]'},
    }

    def __init__(self, **kwargs):
        super(CustomRoleDefinition, self).__init__(**kwargs)
        self.id = kwargs.get('id', None)
        self.name = kwargs.get('name', None)
        self.type = kwargs.get('type', None)
        self.role_name = kwargs.get('role_name', None)
        self.description = kwargs.get('description', None)
        self.role_type = kwargs.get('role_type', None)
        self.permissions = kwargs.get('permissions', None)
        self.assignable_scopes = kwargs.get('assignable_scopes', None)


class AzureFactory:
    datalakename = None
    subscription_id = None
    resource_group = None
    storage_account_name = None
    credentials = None
    client_secret_credential = None

    resource_client = None
    compute_client = None
    network_client = None
    authorization_client = None
    storage_client = None
    adls2_client = None
    msi_client = None
    policy_client = None
    role_definitions = None

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
        if os.environ.get('STORAGE_ACCOUNT_NAME') is None:
            raise ValueError('STORAGE_ACCOUNT_NAME environment variable missing')

        self.storage_account_name = os.environ['STORAGE_ACCOUNT_NAME']

        self.credentials = ServicePrincipalCredentials(
            client_id=os.environ['AZURE_CLIENT_ID'],
            secret=os.environ['AZURE_CLIENT_SECRET'],
            tenant=os.environ['AZURE_TENANT_ID']
        )

        #FIXME do we need two credentials?
        self.client_secret_credential = ClientSecretCredential(os.environ['AZURE_TENANT_ID'], os.environ['AZURE_CLIENT_ID'], os.environ['AZURE_CLIENT_SECRET'])

        self.resource_client = ResourceManagementClient(self.credentials, self.subscription_id)
        self.authorization_client = AuthorizationManagementClient(self.credentials, self.subscription_id)
        self.msi_client = ManagedServiceIdentityClient(self.credentials, self.subscription_id)
        self.policy_client = PolicyClient(self.credentials, self.subscription_id)
        self.authorization_client = AuthorizationManagementClient(self.credentials, self.subscription_id)
        self.storage_client = StorageManagementClient(self.credentials, self.subscription_id)
        # adls2 storage client
        self.adls2_client = DataLakeServiceClient(account_url="{}://{}.dfs.core.windows.net".format(
            "https", self.storage_account_name), credential=self.client_secret_credential)

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
        self.create_identities_attach_policies(ddf)
        self.create_storage_attach_MSI(ddf)

    def create_storage_attach_MSI(self, ddf):
        #self.create_storage_account_if_not_exist()
        self.create_containers(ddf)

    # Create containers
    def create_containers(self, ddf):
        for name, storage in ddf['storage'].items():
            # Remove forward and trailing slashes
            container_path = storage['path'].strip('/')
            print(f"Container path is {container_path}")
            # in case they provided us with containers and directories
            paths = container_path.split('/')

            try:
                global file_system_client
                file_system_client = self.adls2_client.create_file_system(file_system=paths[0])
                print(f"Container {paths[0]} created under storage account {self.storage_account_name}")
            except Exception as e:
                if 'The specified container already exists' in str(e):
                    print(f"Container {paths[0]} already exists under storage account {self.storage_account_name}")
                else:
                    raise ValueError(f"Error creating storage account {paths[0]}, reason {str(e)} ")
            # create directories if required
            if len(paths) > 1:
                for p in paths[1:]:
                    try:
                        file_system_client.create_directory(p)
                    except Exception as e:
                        raise ValueError(f"Error creating directory {p} for account {paths[0]}, reason {str(e)} ")



    ''' Do we need this? keeping it just in case
    https://docs.microsoft.com/en-us/azure/developer/python/azure-sdk-example-storage?tabs=cmd#3-write-code-to-provision-storage-resources
    '''
    def create_storage_account_if_not_exist(self):
        # Check if the account name is available. Storage account names must be unique across
        # Azure because they're used in URLs.
        availability_result = self.storage_client.storage_accounts.check_name_availability(self.storage_account_name)

        if not availability_result.name_available:
            print(f"Storage name {self.storage_account_name} exists.")
            return
        else:
            # let's provision the account
            poller = self.storage_client.storage_accounts.create(self.resource_group, self.storage_account_name,
                                                                 {
                                                                     "location": LOCATION,
                                                                     "kind": "StorageV2",
                                                                     "sku": {"name": "Standard_LRS"}
                                                                 }
                                                                 )

        # Long-running operations return a poller object; calling poller.result()
        # waits for completion.
        account_result = poller.result()
        print(f"Provisioned storage account {account_result.name}")

        # Step 3: Retrieve the account's primary access key and generate a connection string.
        keys = self.storage_client.storage_accounts.list_keys(self.resource_group, self.storage_account_name)

        print(f"Primary key for storage account: {keys.keys[0].value}")

        conn_string = f"DefaultEndpointsProtocol=https;EndpointSuffix=core.windows.net;AccountName={self.storage_account_name};AccountKey={keys.keys[0].value}"

        print(f"Connection string: {conn_string}")

    '''
    Function to create new MSIs if they do not already exist
    and create custom roles, if they do not exist and then attach them 
    to the MSIs.
    '''

    def create_identities_attach_policies(self, ddf):
        self.datalakename = ddf['datalake']
        for name, role in ddf['datalake_roles'].items():
            role_name = role['iam_role']
            user_assigned_identity = self.create_MSI(role_name)
            path = 'datalakes/' + ddf['datalake'] + '/Azure/'
            filename_base = path + role_name + '-policy.json'

            if os.path.exists(filename_base):
                with open(filename_base, "r") as policy:
                    rules = json.load(policy)
            else:
                raise ValueError(f"Could not load policy file {filename_base}")

            self.create_policy_definition(rules['Name'], rules)

            self.assign_policy_to_msi(user_assigned_identity.principal_id, rules['Name'])

    def create_MSI(self, identity):
        self.resource_group = os.environ.get('AZURE_RESOURCE_GROUP',
                                             self.datalakename + 'RG')  # your Azure resource group
        # Create a RG if not already.
        self.create_resource_group()

        try:
            if user_assigned_identity := self.msi_client.user_assigned_identities.get(self.resource_group,
                                                                                      identity,
                                                                                      # Any name, just a human readable ID
                                                                                      custom_headers=None):
                print(f"identity {identity} already exists")
        except CloudError:
            user_assigned_identity = self.msi_client.user_assigned_identities.create_or_update(
                self.resource_group,
                identity,  # Any name, just a human readable ID
                LOCATION
            )
            print(
                f"Created MSI {user_assigned_identity.id} for Datalake {self.datalakename} in resource group {self.resource_group}")
        return user_assigned_identity

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
                self.resource_group_object = rg
                self.resource_group_exists = True
                print(f"Resource group {self.resource_group} already exists.")
                return

        # Provision the resource group.
        self.resource_group_object = self.resource_client.resource_groups.create_or_update(
            self.resource_group,
            {
                "location": LOCATION
            }
        )
        self.resource_group_exists = True
        print(
            f"Provisioned resource group {self.resource_group_object.name} in the {self.resource_group_object.location} region")

        # Delete RG - proceed with caution.

    def delete_resource_group(self):
        self.resource_client.resource_groups.delete(self.resource_group)

    def create_policy_definition(self, role_name, rules):
        # Get "Contributor" built-in role as a RoleDefinition object
        roles = list(self.authorization_client.role_definitions.list(
            self.resource_group_object.id,
            filter="roleName eq '{}'".format(role_name)
        ))

        if len(roles):
            print(f"Role {role_name} already exists")
            return

        role_id = uuid.uuid4()
        permission = Permission(actions=rules['Actions'],
                                not_actions=rules['NotActions'],
                                data_actions=rules['DataActions'])

        properties = RoleDefinitionProperties(role_name=role_name,
                                              description=rules['Description'],
                                              type='CustomRole',
                                              assignable_scopes=rules['AssignableScopes'],
                                              permissions=[permission])

        definition = CustomRoleDefinition(id=role_id, name=rules['Name'], role_name=role_name,
                                          description=rules['Description'], role_type='CustomRole',
                                          permissions=[permission], assignable_scopes=rules['AssignableScopes'])

        result = self.authorization_client.role_definitions.create_or_update(role_definition_id=role_id,
                                                                             scope=properties.assignable_scopes[0],
                                                                             role_definition=definition)

        if result is not None:
            print(f"Successfully created role {role_name}")
        else:
            print(f"Failed to create role {role_name}")

    '''
    Function to assign policy to a given role.
    This function assumes that the MSI and policy exists.
    '''

    def assign_policy_to_msi(self, msi_name, policy_name):
        roles = list(self.authorization_client.role_definitions.list(self.resource_group_object.id,
                                                                     filter="roleName eq '{}'".format(policy_name)))
        assert len(roles) == 1, f"Role {policy_name} not found"
        result_role = roles[0]

        # FIXME - Do we need assumer to be subscription level?
        # For assumer identity permissions are scoped to Subscription level for rest ar RG level
        if 'Assumer' in policy_name:
            scope = self.resource_group_object.id.split("/resourceGroups")[0]
        else:
            scope = self.resource_group_object.id

        try:
            role_assignment = self.authorization_client.role_assignments.create(
                scope,
                uuid.uuid4(),  # Role assignment random name
                {
                    'role_definition_id': result_role.id,
                    'principal_id': msi_name
                }
            )
            print(f"Successfully assigned role: {policy_name} to MSI: {msi_name}")
            return role_assignment
        except CloudError as e:
            if 'role assignment already exists' in str(e):
                print(f"Role: {policy_name} already attached to MSI: {msi_name}")
            else:
                raise ValueError(f"Error attaching role: {policy_name} to MSI: {msi_name}, reason: {str(e)}")

    def __str__(self):
        return "Azure"
