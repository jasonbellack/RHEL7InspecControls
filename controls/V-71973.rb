control "xccdf_mil.disa.stig_rule_SV-86597r2_rule" do
  title "The Red Hat Enterprise Linux operating system must be configured so that a file integrity tool verifies the baseline operating system configuration at least weekly."
  desc  "
    Vulnerability Discussion: Unauthorized changes to the baseline configuration could make the system vulnerable to various attacks or allow unauthorized access to the operating system. Changes to operating system configurations can have unintended side effects, some of which may be relevant to security.
    
    Detecting such changes and providing an automated response can help avoid unintended, negative consequences that could ultimately affect the security state of the operating system. The operating system's Information Management Officer (IMO)/Information System Security Officer (ISSO) and System Administrators (SAs) must be notified via email and/or monitoring system trap when there is an unauthorized modification of a configuration item.
    
    Documentable: false
    
  "
  impact 0.5
  describe package("aide") do
    it { should be_installed }
  end
  describe.one do
    describe file("/etc/crontab") do
      its("content") { should match(/^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/) }
    end
    file("/etc/crontab").content.to_s.scan(/^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/).flatten.each do |entry|
      describe entry do
        it { should match(/((?:[1-5]?[0-9]|\*)[ \t]+(?:[1]?[0-9]|2[0-3]|\*)[ \t]+\*[ \t]+\*[ \t]+(?:[0-7]|sun|mon|tue|wed|thu|fri|sat))/) }
      end
    end
    file("/etc/crontab").content.to_s.scan(/^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/).flatten.each do |entry|
      describe entry do
        it { should match(/((?:[1-5]?[0-9]|\*)[ \t]+(?:[1]?[0-9]|2[0-3])[ \t]+\*[ \t]+\*[ \t]+(?:[0-7]|sun|mon|tue|wed|thu|fri|sat|\*))/) }
      end
    end
    file("/etc/crontab").content.to_s.scan(/^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/).flatten.each do |entry|
      describe entry do
        it { should match(/((?:[1-5]?[0-9])[ \t]+(?:[1]?[0-9]|2[0-3]|\*)[ \t]+\*[ \t]+\*[ \t]+(?:[0-7]|sun|mon|tue|wed|thu|fri|sat|\*))/) }
      end
    end
    files = command("find /etc/cron.d -type f -regex .\\*/\\^.\\+\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/ } do
      it { should_not be_empty }
    end
    describe file("/var/spool/cron/root") do
      its("content") { should match(/^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/) }
    end
    file("/var/spool/cron/root").content.to_s.scan(/^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/).flatten.each do |entry|
      describe entry do
        it { should match(/((?:[1-5]?[0-9]|\*)[ \t]+(?:[1]?[0-9]|2[0-3]|\*)[ \t]+\*[ \t]+\*[ \t]+(?:[0-7]|sun|mon|tue|wed|thu|fri|sat))/) }
      end
    end
    file("/var/spool/cron/root").content.to_s.scan(/^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/).flatten.each do |entry|
      describe entry do
        it { should match(/((?:[1-5]?[0-9]|\*)[ \t]+(?:[1]?[0-9]|2[0-3])[ \t]+\*[ \t]+\*[ \t]+(?:[0-7]|sun|mon|tue|wed|thu|fri|sat|\*))/) }
      end
    end
    file("/var/spool/cron/root").content.to_s.scan(/^[ \t]*([\S]+[ \t]+[\S]+[ \t]+\*[ \t]+\*[ \t]+[\S]+)[ \t]+root[ \t]+\/usr\/sbin\/aide[ \t]+\-\-check(?:[\s]+|[\>\|]|$)/).flatten.each do |entry|
      describe entry do
        it { should match(/((?:[1-5]?[0-9])[ \t]+(?:[1]?[0-9]|2[0-3]|\*)[ \t]+\*[ \t]+\*[ \t]+(?:[0-7]|sun|mon|tue|wed|thu|fri|sat|\*))/) }
      end
    end
    files = command("find /etc/cron.daily -type f -regex .\\*/\\^.\\+\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[ \t]*\/usr\/sbin\/aide[ \t]*\-\-check(?:[\s]+|[\>\|]|$)/ } do
      it { should_not be_empty }
    end
    files = command("find /etc/cron.weekly -type f -regex .\\*/\\^.\\+\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[ \t]*\/usr\/sbin\/aide[ \t]*\-\-check(?:[\s]+|[\>\|]|$)/ } do
      it { should_not be_empty }
    end
    files = command("find /etc/cron.hourly -type f -regex .\\*/\\^.\\+\\$").stdout.split
    describe files.delete_if { |f| command("file #{f} | cut -d: -f2").stdout =~ /binary|executable|archive/ || file(f).content !~ /^[ \t]*\/usr\/sbin\/aide[ \t]*\-\-check(?:[\s]+|[\>\|]|$)/ } do
      it { should_not be_empty }
    end
  end
end
