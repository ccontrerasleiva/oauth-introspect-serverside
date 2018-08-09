<?php

namespace Tiandgi\OAuthIntrospection\Providers;

use Ipunkt\Laravel\PackageManager\Providers\RouteServiceProvider;

class RouteProvider extends RouteServiceProvider
{
	protected $packagePath = __DIR__ . '/../../';
	protected $routesNamespace = '\Tiandgi\OAuthIntrospection\Http\Controllers';
	protected $routesMiddleware = null;
	protected $routesFile = 'routes/web.php';
}
