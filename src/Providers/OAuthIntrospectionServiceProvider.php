<?php

namespace Tiandgi\OAuthIntrospection\Providers;

use Illuminate\Support\AggregateServiceProvider;

class OAuthIntrospectionServiceProvider extends AggregateServiceProvider
{
	protected $providers = [
		RouteProvider::class,
	];
}