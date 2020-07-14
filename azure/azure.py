import os

# Variable name for template dir
template_dir = 'templates'
datalake_dir = 'datalakes'


class AzureFactory:
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
                        d = dict()
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
                              role['iam_role'] + ' which has been granted: ' + perm_name)
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
                #elif elements[0] == 'db':

                i = i + 1

    def __str__(self):
        return "Azure"
