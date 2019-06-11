control "xccdf_mil.disa.stig_rule_SV-86795r6_rule" do
  title "The Red Hat Enterprise Linux operating system must audit all uses of the mount command and syscall."
  desc  "
    Vulnerability Discussion: Reconstruction of harmful events or forensic analysis is not possible if audit records do not contain enough information.
    
    At a minimum, the organization must audit the full-text recording of privileged mount commands. The organization must maintain audit trails in sufficient detail to reconstruct events to determine the cause and impact of compromise.
    
    Satisfies: SRG-OS-000042-GPOS-00020, SRG-OS-000392-GPOS-00172
    
    Documentable: false
    
  "
  impact 0.5
  if file('/usr/lib/systemd/system/auditd.service').content =~ /^ExecStartPost=\-\/sbin\/augenrules.*$/
  
    describe file('/usr/lib/systemd/system/auditd.service') do
      its('content') { should match /^ExecStartPost=\-\/sbin\/augenrules.*$/ }
    end
  
    config_files = command('find /etc/audit/rules.d -regex ".*\.rules$"').stdout.split
    describe config_files do
      its('length') { should cmp > 0 }
    end
    describe.one do
      config_files.each do |config_file|
        describe file(config_file) do
          its('content') { should match /^\-a\s+always,exit\s+(?:(-F[\s]+path=\/usr\/bin\/mount[\s]+))(?:-F\s+auid>=1000\s+\-F\s+auid!=4294967295\s+)(-k[\s]+|-F[\s]+key=)[-\w]+\s*$/ }
        end
      end
    end
  
    if os[:arch] =~ /64/
      config_files = command('find /etc/audit/rules.d -regex ".*\.rules$"').stdout.split
      describe.one do
        config_files.each do |config_file|
          describe file(config_file) do
            its('content') { should match /^\-a\s+always,exit\s+(\-F\s+arch=b64\s+)(?:.*(-S[\s]+mount[\s]+|([\s]+|[,])mount([\s]+|[,])))(?:.*-F\s+auid>=1000\s+\-F\s+auid!=4294967295\s+)(-k[\s]+|-F[\s]+key=)[-\w]+\s*$/ }
          end
        end
      end
    else
      describe os[:arch] do
        it { should match /32/ }
      end
    end
  
  else # auditctl must be used if not augenrules
  
    describe file('/usr/lib/systemd/system/auditd.service') do
      its('content') { should match /^ExecStartPost=\-\/sbin\/auditctl.*$/ }
    end
  
    describe file('/etc/audit/audit.rules') do
      its('content') { should match /^\-a\s+always,exit\s+(?:(-F[\s]+path=\/usr\/bin\/mount[\s]+))(?:-F\s+auid>=1000\s+\-F\s+auid!=4294967295\s+)(-k[\s]+|-F[\s]+key=)[-\w]+\s*$/ }
    end
  
    if os[:arch] =~ /64/
      describe file('/etc/audit/audit.rules') do
        its('content') { should match /^\-a\s+always,exit\s+(\-F\s+arch=b64\s+)(?:.*(-S[\s]+mount[\s]+|([\s]+|[,])mount([\s]+|[,])))(?:.*-F\s+auid>=1000\s+\-F\s+auid!=4294967295\s+)(-k[\s]+|-F[\s]+key=)[-\w]+\s*$/ }
      end
    else
      describe os[:arch] do
        it { should match /32/ }
      end
    end
  end
end
