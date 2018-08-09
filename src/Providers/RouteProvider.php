<?php

namespace Tiandgi\OAuthIntrospection\Providers;

use Illuminate\Contracts\Routing\Registrar as Router;

class RouteProvider{
    protected $router;
    
    public function __construct(Router $router)
    {
        $this->router = $router;
    }
    
    public function all()
    {
        $this->forValidToken();
    }
    
    private function forValidToken(){
        $router->post('/oauth/validToken', [
                'uses' => 'IntrospectionController@validToken',
            ]);
    }
}

