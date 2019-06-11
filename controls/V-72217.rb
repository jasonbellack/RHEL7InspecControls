control "xccdf_mil.disa.stig_rule_SV-86841r2_rule" do
  title "The Red Hat Enterprise Linux operating system must limit the number of concurrent sessions to 10 for all accounts and/or account types."
  desc  "
    Vulnerability Discussion: Operating system management includes the ability to control the number of users and user sessions that utilize an operating system. Limiting the number of allowed users and sessions per user is helpful in reducing the risks related to DoS attacks.
    
    This requirement addresses concurrent sessions for information system accounts and does not address concurrent sessions by single users via multiple system accounts. The maximum number of concurrent sessions should be defined based on mission needs and the operational environment for each system.
    
    Documentable: false
    
  "
  impact 0.1
  limits_d_files = command("find /etc/security/limits.d -type f -regex \\^.\\*\\\\.conf\\$").stdout.split
  limits_d_files_with_maxlogins = Array.new
  limits_d_files.each do |f|
    if file(f).content =~ /^[\s]*\*[\s]+(?:(?:hard)|(?:-))[\s]+maxlogins[\s]+(\d+)\s*$/
      limits_d_files_with_maxlogins.push(f)
    end
  end
  if limits_d_files.sort == limits_d_files_with_maxlogins.sort
    limits_d_files_with_maxlogins.each do |f|
      file(f).content.to_s.scan(/^[\s]*[^#\s]+[\s]+(?:(?:hard)|(?:-))[\s]+maxlogins[\s]+(\d+)\s*$/).flatten.each do |maxlogins|
        describe maxlogins do
          it { should cmp <= 10 }
        end
      end
    end
  else
    describe limits_d_files_with_maxlogins do
      it { should be_empty }
    end
    file("/etc/security/limits.conf").content.to_s.scan(/^[\s]*[^#\s]+[\s]+(?:(?:hard)|(?:-))[\s]+maxlogins[\s]+(\d+)\s*$/).flatten.each do |maxlogins|
      describe maxlogins do
        it { should cmp <= 10 }
      end
    end
  end
end
