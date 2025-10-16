from dynint.dyntrace import sampling


def test_sampler_every_third_event():
    sampler = sampling.SamplerFactory.from_spec("1/3")
    results = [sampler.allow() for _ in range(6)]
    assert results == [False, False, True, False, False, True]


def test_sampler_disabled_when_spec_none():
    assert sampling.SamplerFactory.from_spec(None) is None


def test_sampler_parse_integer_spec():
    sampler = sampling.SamplerFactory.from_spec("5")
    assert sampler.denominator == 1
    assert sampler.numerator == 5
