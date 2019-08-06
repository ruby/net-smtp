require "test_helper"

class Net::SmtpTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::Net::Smtp::VERSION
  end

  def test_it_does_something_useful
    assert false
  end
end
