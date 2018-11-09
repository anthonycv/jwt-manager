<?php

use Anthonycv\JwtManager\JwtManager;

class JwtTest extends PHPUnit_Framework_TestCase
{

    public function testExample()
    {

        $jwtManager = new JwtManager();

        $claims = [
            'aud' => '190.237.41.61',
            'uid' => '15',
        ];

//        $jwt = $jwtManager->issue($claims);
//
//        print_r($jwt);
//        die('..');

//        $jwtDecoded = $jwtManager->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJqdGkiOiJhZDhlZWMzMy1lYmYwLTQzMDEtYWQ5Ny1lMDA2YTE3ZDNjMzIiLCJpYXQiOjE1NDE3MTMwODAsIm5iZiI6MTU0MTcxMzA4MCwiYXVkIjoiMTkwLjIzNy40MS42MSIsInVpZCI6IjE1IiwiZXhwIjoxNTQyMzExODgwLCJydGkiOiJhYzJiZDYyNS1hYTcxLTQ3NjItYTkwMC02NTAxNGEwY2VjOGMifQ.LbufEPtU2Y-H0M-3e_ZburFFjN4OjYIb8i7jQoTAmQn_1uhA0jqUrMJ19fZptXCP');

//        print_r($jwtDecoded->jti);
//        die('..');
//
//        echo $jwtManager->removeWhiteList('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJqdGkiOiJlODk4YmY3Ni0xYTg0LTQ2NDEtYTdjNC1iN2IxZWE5MTk1YWUiLCJpYXQiOjE1NDE3MTMyODgsIm5iZiI6MTU0MTcxMzI4OCwiYXVkIjoiMTkwLjIzNy40MS42MSIsInVpZCI6IjE1IiwiZXhwIjoxNTQxNzE0MTg4LCJydHQiOiJjMzRhMDE2NC00NmFmLTQ1MzgtYjM0ZC1hNzk2MjE0MDc1NGEifQ.EBKNYeWaMqH9V4O_KSK1o3xAtgnPWS3hhWrSN4onxcwxfyTCMHa7QHakF6jJKi3X');
//        die('..');
//
        $response = $jwtManager->validate('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJqdGkiOiJiOWQ1NDFiMS1hM2I2LTRkYjMtOWQ1YS0wMDU2NDExYWY1YjciLCJpYXQiOjE1NDE3MTQzMzEsIm5iZiI6MTU0MTcxNDMzMSwiYXVkIjoiMTkwLjIzNy40MS42MSIsInVpZCI6IjE1IiwiZXhwIjoxNTQyMzEzMTMxLCJydGkiOiI4YzQzOGQzNS0wYmY3LTQzMmUtODEwMC0yYTU3YjgyY2Q0YzUifQ.nf1a2kYZ4DTN4f_yem2sfLDCgEzJOF4O4IKky7ej6gq9rm8Rs7s5ylyIoUJHV8Aq');

        print_r($response);
        die('..');

    }





}