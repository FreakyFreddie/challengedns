import os
from flask import Blueprint, render_template, request, abort, redirect, url_for
from CTFd.utils import admins_only, is_admin
from CTFd.models import db

import json

from subprocess import Popen, PIPE, STDOUT
import shlex

from .models import *
from .blacklist import *

def load(app):
    #create tables
    app.db.create_all()

    # create plugin blueprint with template folder
    challengedns = Blueprint('challengedns', __name__, template_folder='templates')

    #valid configuration settions with their type
    valid_settings ={
        'DNS IP': ['text', '10.0.7.4'],
        'Root domain': ['text', 'ctf.be'],
        'Nameserver': ['text', 'ns1.ctf.be'],
        'Keyfile': ['text', '/opt/CTFd/nsupdate.key'],
        'Port': ['number', '53']
    }

    delete_format = '''\
            server {0}
            update delete {1} A
            send\
            '''

    create_format = '''\
        server {0}
        update add {1} {2} A {3}
        send\
        '''

    update_format = '''\
        server {0}
        update delete {1} A
        send
        server {0}
        update add {1} {2} A {3}
        send\
        '''

    # Set up route to configuration interface
    @challengedns.route('/admin/challengedns/configure', methods=['GET', 'POST'])
    @admins_only
    def configure():
        if request.method == 'POST':
            settings = {}
            errors = []

            for key in valid_settings:
                if key in request.form:
                    settings[key]=[valid_settings[key][0], request.form[key]]
                else:
                    errors.append("%s is not a valid setting." % key)

            # error handling
            if len(errors) > 0:
                return render_template('init_settings.html', errors=errors, settings=settings)
            else:
                #write all key-value pairs to database & redirect to manage
                for key in settings:
                    challengednsconfig = challengeDNSConfig.query.filter_by(option=key).first()

                    # if key does not exist in database, add entry, else update
                    if challengednsconfig == None:
                        challengednsconfig = challengeDNSConfig(key,settings[key][1])
                        db.session.add(challengednsconfig)
                        db.session.commit()
                        db.session.flush()
                    else:
                        challengednsconfig.value = settings[key][1]
                        db.session.commit()
                        db.session.flush()

                return redirect(url_for('.manage'), code=302)

        else:
            # generate dictionary with already filled in config options + empty options
            settings = config_opts_db()

            return render_template('init_settings.html', settings=settings)


    # Set up route to management interface
    @challengedns.route('/admin/challengedns/manage', methods=['GET'])
    @admins_only
    def manage():
        if not is_configured():
            return redirect(url_for('.configure'), code=302)
        else:
            errors = []
            records = []

            #if fetch_zone_records failed, return error
            try:
                records = fetch_zone_records()
            except Exception as e:
                print("Caught Exception : " + str(e))
                errors.append("Caught Exception : " + str(e))

            if len(errors) > 0:
                return render_template('manage.html', errors=errors, dns_records=[])

            return render_template('manage.html', dns_records=records)


    @challengedns.route('/admin/challengedns/manage/update', methods=['POST'])
    @admins_only
    def update_list():
        try:
            records = fetch_zone_records()
        except Exception as e:
            print("Caught Exception : " + str(e))
            return "Caught Exception : " + str(e)

        return json.dumps(records)

    @challengedns.route('/admin/challengedns/manage/record/<string:chalname>/delete', methods=['POST'])
    @admins_only
    def delete_record(chalname):
        try:
            return delete_operation(chalname)
        except Exception as e:
            print("Caught Exception : " + str(e))
            return "Caught Exception : " + str(e)


    @challengedns.route('/admin/challengedns/manage/record/<string:chalname>/update', methods=['POST'])
    @admins_only
    def update_record(chalname):
        if request.form[ipaddress]:
            try:
                return update_operation(chalname)
            except Exception as e:
                print("Caught Exception : " + str(e))
                return "Caught Exception : " + str(e)
        else:
            return "chalname not set."

    @challengedns.route('/admin/challengedns/manage/record/new', methods=['POST'])
    @admins_only
    def create_record():
        if request.form[chalname] and request.form[ipaddress]:
            try:
                return create_operation(chalname, ipaddress)
            except Exception as e:
                print("Caught Exception : " + str(e))
                return "Caught Exception : " + str(e)
        else:
            return "ipaddress or chalname not set."

    def delete_operation(hostname):
        #check if exists
        #delete
        nameserver = challengeDNSConfig.query.filter_by(option="DNS IP").first()

        if nameserver and hostname:
            operation = delete_format.format(
                nameserver,
                hostname)
            return_code, stdout = nsupdate(operation)
            if return_code != 0:
                return stdout
            else:
                print('Record deleted.')
                return "Success!"
        else:
            print("Parameters not correct.")
            return "Parameters not correct."

    def update_operation(hostname, ipaddress):
        #check if exists
        #update record
        nameserver = challengeDNSConfig.query.filter_by(option="DNS IP").first()

        if nameserver and hostname and ipaddress:
            operation = update_format.format(
                nameserver,
                hostname,
                8640,
                ipaddress)

            return_code, stdout = nsupdate(operation)
            if return_code != 0:
                return stdout
            else:
                print('Record updated')
                return "Success!"
        else:
            print("Parameters not correct.")
            return "Parameters not correct."

    def create_operation(hostname, ipaddress):
        # check if exists
        # update record
        nameserver = challengeDNSConfig.query.filter_by(option="DNS IP").first()

        if nameserver and hostname and ipaddress:
            operation = create_format.format(
                nameserver,
                hostname,
                8640,
                ipaddress)

            return_code, stdout = nsupdate(operation)
            if return_code != 0:
                return stdout
            else:
                print('Record created.')
                return "Success!"

        else:
            print("Parameters not correct.")
            return "Parameters not correct."


    def nsupdate(update):
        keyfile = challengeDNSConfig.query.filter_by(option="Keyfile").first()

        cmd = 'nsupdate -k {0}'.format(keyfile)

        # open subprocess and execute nsupdate cmd
        # shlex.split() splits the cmd string using shell-like syntax
        subp = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)

        stdout =subp.communicate(input=update)[0]

        return subp.returncode, stdout.decode()

    def output_zone_records(rootdomain, nameserver):
        cmd = 'dig @{0} {1} axfr'.format(nameserver, rootdomain)

        # open subprocess and execute nsupdate cmd
        # shlex.split() splits the cmd string using shell-like syntax
        subp = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)

        stdout =subp.communicate(input=update)[0]

        # only show A records, not NS, SOA or any other
        # remove comments (lines starting with ;;)

        return subp.returncode, stdout.decode()

    def fetch_zone_records():
        rootdomain = challengeDNSConfig.query.filter_by(option="Root domain").first()
        nameserver = challengeDNSConfig.query.filter_by(option="Nameserver").first()

        return_code, cmd_output = output_zone_records(rootdomain, nameserver)
        records = []

        recs = cmd_output.splitlines()

        for rec in recs:
            record = rec.split()

            # Only append A records
            if record[3] == "A":
                rootdomain += "."
                chalname = record[0].replace(rootdomain, "")

                # Append only
                if chalname not in chalname_blacklist:
                    records.append(record)

        return records


    def fetch_vm_by_uuid(vm_uuid, service_instance):
        try:
            vm = service_instance.content.searchIndex.FindByUuid(None, vm_uuid,
                                                   True,
                                                   True)
            return vm
        except:
            raise # "Unable to locate VirtualMachine."


    # plugin is not configured when one key has no value
    def is_configured():
        configured = True

        for key in valid_settings:
            challengednsconfigopt = challengeDNSConfig.query.filter_by(option=key).first()
            if challengednsconfigopt == None:
                configured = False

        return configured


    # generate dictionary with already filled in config options + empty options
    def config_opts_db():
        settings = {}

        for key in valid_settings:
            challengednsconfigopt = challengeDNSConfig.query.filter_by(option=key).first()

            if challengednsconfigopt == None:
                settings[key] = [valid_settings[key][0], valid_settings[key][1]]
            else:
                settings[key] = [valid_settings[key][0], challengednsconfigopt.value]

        return settings


    def connect_to_vsphere():
        challengednsconfigusername = challengednsConfig.query.filter_by(option="Username").first()
        challengednsconfigpassword = challengednsConfig.query.filter_by(option="Password").first()
        challengednsconfighost = challengednsConfig.query.filter_by(option="Host").first()
        challengednsconfigport = challengednsConfig.query.filter_by(option="Port").first()

        username = challengednsconfigusername.value
        password = challengednsconfigpassword.value
        host = challengednsconfighost.value
        port = challengednsconfigport.value

        print("Attempting connection to vCenter...")

        context = ssl._create_unverified_context()
        service_instance = connect.SmartConnect(host=host,
                                                user=username,
                                                pwd=password,
                                                port=int(port),
                                                sslContext=context)

        atexit.register(connect.Disconnect, service_instance)

        return service_instance


    def fetch_vm_list(service_instance):
        content = service_instance.RetrieveContent()

        # search recursively from root folder and return all found VirtualMachine objects
        containerView = content.viewManager.CreateContainerView(
            content.rootFolder, [vim.VirtualMachine], True)

        virtual_machines = containerView.view
        containerView.Destroy()

        return virtual_machines


    # function to update VM on/off status
    # less data to lower network load
    def fetch_vm_list_online_offline():
        virtual_machines = fetch_vm_list(connect_to_vsphere())

        vms = []

        for virtual_machine in virtual_machines:
            summary = virtual_machine.summary

            name = summary.config.name
            template = summary.config.template
            blacklisted = False

            # if vm is template, exclude
            if template:
                continue

            # if vm is blacklisted, skip this iteration
            for blacklisted_vm in vm_blacklist:
                if name == blacklisted_vm['Name']:
                    blacklisted = True
            if blacklisted:
                continue

            instance_uuid = summary.config.instanceUuid
            state = summary.runtime.powerState

            if summary.guest is not None:
                if summary.guest.ipAddress:
                    ipaddress = summary.guest.ipAddress
                else:
                    ipaddress = "Unknown"

                if summary.guest.toolsRunningStatus is not None:
                    vmwaretools = summary.guest.toolsRunningStatus
                else:
                    vmwaretools = "guestToolsNotRunning"
            else:
                ipaddress = "Unknown"
                vmwaretools = "guestToolsNotRunning"

            # append VM to array
            vms.append({
                "Name": name,
                "UUID": instance_uuid,
                "State": state,  # powereedOff, poweredOn, ??StandBy, ??unknown, suspended
                "Ipaddress": ipaddress,
                "Vmwaretools": vmwaretools
            })

        return vms


    # returns when tasklist is finished
    def WaitForTasks(tasks, service_instance):
        pc = service_instance.content.propertyCollector

        taskList = [str(task) for task in tasks]

        # Create filter
        objSpecs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task)
                    for task in tasks]
        propSpec = vmodl.query.PropertyCollector.PropertySpec(type=vim.Task,
                                                              pathSet=[],
                                                              all=True)
        filterSpec = vmodl.query.PropertyCollector.FilterSpec()
        filterSpec.objectSet = objSpecs
        filterSpec.propSet = [propSpec]
        filter = pc.CreateFilter(filterSpec, True)

        try:
            version, state = None, None

            # Loop looking for updates till the state moves to a completed state.
            while len(taskList):
                update = pc.WaitForUpdates(version)
                for filterSet in update.filterSet:
                    for objSet in filterSet.objectSet:
                        task = objSet.obj
                        for change in objSet.changeSet:
                            if change.name == 'info':
                                state = change.val.state
                            elif change.name == 'info.state':
                                state = change.val
                            else:
                                continue

                            if not str(task) in taskList:
                                continue

                            if state == vim.TaskInfo.State.success:
                                # Remove task from taskList
                                taskList.remove(str(task))
                            elif state == vim.TaskInfo.State.error:
                                raise task.info.error
                # Move to next version
                version = update.version
        finally:
            if filter:
                filter.Destroy()


    def powerstate_operation(vm_uuid, operation):
        tasks = []

        try:
            service_instance = connect_to_vsphere()
        except (IOError, vim.fault.InvalidLogin):
            print("SmartConnect to vCenter failed.")
            return "SmartConnect to vCenter failed."
        except Exception as e:
            print("Caught Exception : " + str(e))
            return "Caught Exception : " + str(e)

        try:
            vm = fetch_vm_by_uuid(vm_uuid, service_instance)
        except Exception as e:
            return "Caught Exception : " + str(e)

        for blacklisted_vm in vm_blacklist:
            if vm.summary.config.name == blacklisted_vm['Name']:
                print("Operation failed.")
                return "Operation failed."


        # only call powerOn on vm that is off and matches uuid
        if(vm.summary.runtime.powerState == "poweredOff"):
            # only call powerOn on vm that is off and matches uuid
            if (operation == "powerOn"):
                try:
                    tasks.append(vm.PowerOn())

                    # Wait for power on to complete
                    WaitForTasks(tasks, service_instance)

                except vmodl.MethodFault as e:
                    return "Caught vmodl fault : " + e.msg
                except Exception as e:
                    return "Caught Exception : " + str(e)

                print("Task complete.")
                return "Success!"


        elif(vm.summary.runtime.powerState == "poweredOn"):
            if (operation == "Suspend"):
                try:
                    tasks.append(vm.Suspend())

                    # Wait for task to complete
                    WaitForTasks(tasks, service_instance)

                except vmodl.MethodFault as e:
                    return "Caught vmodl fault : " + e.msg
                except Exception as e:
                    return "Caught Exception : " + str(e)

                print("Task complete.")
                return "Success!"

            elif (operation == "Shutdown"):
                try:
                    # This task returns nothing since it's executed in the guest VM
                    tasks.append(vm.ShutdownGuest())

                except vmodl.MethodFault as e:
                    return "Caught vmodl fault : " + e.msg
                except Exception as e:
                    return "Caught Exception : " + str(e)

                print("Shutdown signal send.")
                return "Shutdown signal send."

            elif (operation == "Reboot"):

                try:
                    # This task returns nothing since it's executed in the guest VM
                    vm.RebootGuest()

                except vmodl.MethodFault as e:
                    return "Caught vmodl fault : " + e.msg
                except Exception as e:
                    return "Caught Exception : " + str(e)

                print("Reboot signal send.")
                return "Reboot signal send."

        elif(vm.summary.runtime.powerState == "suspended"):
            if (operation == "Resume"):
                try:
                    tasks.append(vm.PowerOn())

                    # Wait for power on to complete
                    WaitForTasks(tasks, service_instance)

                except vmodl.MethodFault as e:
                    return "Caught vmodl fault : " + e.msg
                except Exception as e:
                    return "Caught Exception : " + str(e)

                print("Taks complete.")
                return "Success!"

        else:
            return "requirements not met."

    app.register_blueprint(challengedns)