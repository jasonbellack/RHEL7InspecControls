control "xccdf_mil.disa.stig_rule_SV-86811r4_rule" do
  title "The Red Hat Enterprise Linux operating system must audit all uses of the delete_module syscall."
  desc  "
    Vulnerability Discussion: Without generating audit records that are specific to the security and mission needs of the organization, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.
    
    Audit records can be generated from various components within the information system (e.g., module or policy filter).
    
    Satisfies: SRG-OS-000471-GPOS-00216, SRG-OS-000477-GPOS-00222
    
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
    if os[:arch] =~ /32/
    describe.one do
      config_files.each do |config_file|
        describe file(config_file) do
          its('content') { should match /^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ }
        end
      end
    end
   end
    if os[:arch] =~ /64/
      config_files = command('find /etc/audit/rules.d -regex ".*\.rules$"').stdout.split
      describe.one do
        config_files.each do |config_file|
          describe file(config_file) do
            its('content') { should match /^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ }
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
      its('content') { should match /^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b32[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ }
    end
  
    if os[:arch] =~ /64/
      describe file('/etc/audit/audit.rules') do
        its('content') { should match /^[\s]*-a[\s]+always,exit[\s]+(?:.*-F[\s]+arch=b64[\s]+)(?:.*(-S[\s]+delete_module[\s]+|([\s]+|[,])init_module([\s]+|[,]))).*(-k[\s]+|-F[\s]+key=)[\S]+[\s]*$/ }
      end
    else
      describe os[:arch] do
        it { should match /32/ }
      end
    end
  end
end
