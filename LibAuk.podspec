Pod::Spec.new do |s|
  s.name             = 'LibAuk'
  s.version          = '0.1.1'
  s.summary          = 'Autonomy KMS written in Swift.'
  s.homepage         = 'https://bitmark.com'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Bitmark Inc' => 'support@bitmark.com' }
  s.source           = { :git => 'https://github.com/bitmark-inc/libauk-swift.git', :tag => s.version.to_s }
  s.ios.deployment_target = '14.0'
  s.swift_version = '5.0'
  s.source_files = 'Sources/LibAuk/**/*'
end
