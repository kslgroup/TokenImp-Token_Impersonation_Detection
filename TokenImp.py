# TokenImp.py
# Author: Shachaf Atun (KSL group)
# Email: ksl.taskforce@gmail.com
# Description:
# TokenImp plugin helps you map the processes' and threads' tokens.
# The plugin searches and notifies about every active thread that runs
# with a different token from its owning process.
# That can be within the elevation mode or running user(different domain or user name).
# In addition to that, the plugin will find processes created from diffrent token's context.
# For full documentation and usage: https://github.com/kslgroup/TokenImp-Token_Impersonation_Detection


#Imports
import volatility.plugins.vadinfo as vadinfo
from volatility.plugins.taskmods import PSList
import volatility.plugins.taskmods as taskmods
import volatility.obj as obj

#Globals
ELEVATED_MASK = 0x200


class TokenImp(taskmods.DllList):
    """
    Token Impersonation Detection
    """
    
    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        config.remove_option("BASE")
        config.add_option('SELECT-USERS', short_option='u', type=str, help='select spesific user')
        config.add_option("DETECT-CTRATION", short_option='c',default=False,action='store_true', help='new process detection')


    def get_threads_for_process(self, task):
        """
        :param task: _EPROCESS structure of the process
        :return: a generator of threads from
                 the linked list - _ETHREAD Object
        """

        for thread in task.ThreadListHead.list_of_type("_ETHREAD",
                                                       "ThreadListEntry"):
            yield thread

    def get_proc_name(self, proc, address_space):
        """
        :param proc: _EPROCESS object
        :param address_space: Process's address space object
        :return: The process's loaded image file name
        Extract the process's loaded image file name from
        the _EPROCESS structure
        """
        name = address_space.read(proc.SeAuditProcessCreationInfo.ImageFileName.Name.Buffer,
                                  proc.SeAuditProcessCreationInfo.ImageFileName.Name.Length).replace("\x00", '')

        return name if name else ''


    def get_elevated_info(self,token_flags):
        """
        :param token_flags: unsigned long
        return a string that describes whether the token is eleveted or not
        """
        return "Elevated token" if  token_flags & ELEVATED_MASK ==0 else "Non elevated token"
    
    def calculate(self):

        # Get processes
        ps = PSList(self._config)
        psdata = ps.calculate()

        for proc in psdata:
            
            # get address space
            proc_addr_space = proc.get_process_address_space()
            suspicious_threads = []
            
            proc_token = proc.get_token()
            sus_reason = ""
            
            # Impersonate creation
            if self._config.DETECT_CTRATION:
                if proc.Job != 0 and proc.CrossSessionCreate==1 and proc.OverrideAddressSpace ==0 and proc.WriteWatch == 0: 
                    sus_reason += "\tImpersonate Process Creation Detected \n"

            process_elevated = self.get_elevated_info(proc_token.TokenFlags)

            # checks the select users option
            if self._config.SELECT_USERS:
                users = self._config.SELECT_USERS.split(",")
                proc_full_username = "{}/{}".format(proc_token.LogonSession.AuthorityName,proc_token.LogonSession.AccountName)

                # only selected users
                if proc_full_username not in users:
                    continue
            
            for thread in self.get_threads_for_process(proc):
            
                imp_token = thread.ClientSecurity.ImpersonationToken

                if imp_token:
                    token_offset = thread.ClientSecurity.ImpersonationToken-thread.ClientSecurity.ImpersonationLevel
                    thread_token = obj.Object("_TOKEN",token_offset,proc_addr_space)

                    # validation
                    if thread_token.v() != 0 and thread_token.is_valid() and \
                       thread_token.TokenInUse == 0 and bin(thread.CrossThreadFlags.v())[2:][::-1][3] == "1": 
                     
                        # second validation
                        if thread_token.LogonSession.AuthorityName:
                            
                            # get elevated info
                            elevated = self.get_elevated_info(thread_token.TokenFlags)

                            
                            if self._config.verbose or \
                            elevated != process_elevated or \
                            proc_token.LogonSession.AuthorityName != thread_token.LogonSession.AuthorityName or \
                            proc_token.LogonSession.AccountName != thread_token.LogonSession.AccountName:

                                # non suspicious impersonation
                                if elevated == process_elevated and \
                                proc_token.LogonSession.AuthorityName == thread_token.LogonSession.AuthorityName or \
                                proc_token.LogonSession.AccountName == thread_token.LogonSession.AccountName:
                                    sus_flag = False
                                else:
                                    sus_flag = True
                                    

                                suspicious_threads.append((thread_token.LogonSession.AuthorityName,
                                                           thread_token.LogonSession.AccountName
                                                            ,"".join(chr(i) for i in thread_token.TokenSource.SourceName),
                                                           thread.Cid.UniqueThread,
                                                           elevated))
                                

            #suspicious threads
            if suspicious_threads:

                if sus_flag:
                    sus_reason += "\tActive Impersonated Thread(s) With Differnet Token(s) found \n"
                else:
                    sus_reason += "\tNon suspicious impersonation detected (verbose mode)\n"
                
            # verbose option
            if self._config.verbose:
                sus_reason += "\tVerbose Mode\n"
            
            if sus_reason:
                yield proc,sus_reason,suspicious_threads


    
    def render_text(self, outfd, data):

        outfd.write("\n\nToken Impersonation Information:\n\n")

        for proc,sus_reason,thread_list in data:
            proc_token = proc.get_token()
            elevated = self.get_elevated_info(proc_token.TokenFlags)
            proc_pid = proc.UniqueProcessId
            proc_ppid = proc.InheritedFromUniqueProcessId
            proc_name = proc.ImageFileName.strip()
            address_space = proc.get_process_address_space()

            outfd.write("Proc - {}, Pid - {}, PPid - {} \n".format(proc_name,proc_pid,proc_ppid))
            outfd.write("Detection Reasons:\n{}\n".format(sus_reason))
            outfd.write("Token Info: {}/{} ({})\n".format(proc_token.LogonSession.AuthorityName,
                                                          proc_token.LogonSession.AccountName,
                                                          elevated))

            if thread_list:
                outfd.write("\nThreads With Diffrent token:\n");

                for auth_name,account_name,source,tid,elevated in thread_list:

                    outfd.write("Thread Id:{}\n".format(tid))
                    outfd.write("\t\tToken Info:{}/{} ({}), source - {}\n".format(auth_name,account_name,elevated,source))
                    outfd.write("-"*100)
                    outfd.write("\n")
                    
            outfd.write("-"*100)
            outfd.write("\n")
                
