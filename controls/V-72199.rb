control "xccdf_mil.disa.stig_rule_SV-86823r4_rule" do
  title "The Red Hat Enterprise Linux operating system must audit all uses of the rename syscall."
  desc  "
    Vulnerability Discussion: If the system is not configured to audit certain activities and write them to an audit log, it is more difficult to detect and track system compromises and damages incurred during a system compromise.
    
    Satisfies: SRG-OS-000466-GPOS-00210, SRG-OS-000467-GPOS-00210, SRG-OS-000468-GPOS-00212, SRG-OS-000392-GPOS-00172
    
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
    if os[:arh] =~ /32/
    describe.one do
      config_files.each do |config_file|
        describe file(config_file) do
          its('content') { should match /^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=4294967295[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ }
        end
      end
    end
  end

    if os[:arch] =~ /64/
      config_files = command('find /etc/audit/rules.d -regex ".*\.rules$"').stdout.split
      describe.one do
        config_files.each do |config_file|
          describe file(config_file) do
            its('content') { should match /^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=4294967295[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ }
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
      its('content') { should match /^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=4294967295[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ }
    end
  
    if os[:arch] =~ /64/
      describe file('/etc/audit/audit.rules') do
        its('content') { should match /^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+rename[\s]+|([\s]+|[,])rename([\s]+|[,])))(?:.*-F\s+auid>=1000[\s]+)(?:.*-F\s+auid!=4294967295[\s]+).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ }
      end
    else
      describe os[:arch] do
        it { should match /32/ }
      end
    end
  end
end
