<?php

use Anthonycv\JwtManager\JwtManager;

/**
 * Class JwtTest
 */
class JwtTest extends PHPUnit_Framework_TestCase
{

    /**
     * Generate a issue that contain the jwt.
     *
     * @throws Exception        Each token encoded is a string with 3 segment separated with a dot.
     */
    public function testIssue()
    {

        $jwtManager = new JwtManager();

        $claims = [
            'aud' => '190.237.41.61',
            'uid' => '15',
        ];

        $issue = $jwtManager->issue($claims);

        $commonSplit = explode('.', $issue['common']);
        $this->assertCount(3, $commonSplit);

        $this->assertArrayHasKey('common', $issue);

        if (count($issue) > 1){
            $this->assertArrayHasKey('refresh', $issue);
            $refreshSplit = explode('.', $issue['refresh']);
            $this->assertCount(3, $refreshSplit);
        }


    }

    /**
     * Decoded jwt.
     *
     * @throws Exception        The jwt object contain the key, hash and claims attribute.
     */
    public function testDecoded()
    {

        $jwtManager = new JwtManager(true, 'qwerty', 'HS256');

        $claims = [
            'aud' => '190.237.41.61',
            'uid' => '15',
        ];

        $issue = $jwtManager->issue($claims);


        $valid = $jwtManager->decode($issue['common'], 'HS256');
        $invalid = $jwtManager->decode('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzM4NCJ9.eyJqdGkiOiJhZDhlZWMzMy1lYmYwLTQzMDEtYWQ5Ny1lMDA2YTE3ZDNjMzIiLCJpYXQiOjE1NDE3MTMwODAsIm5iZiI6MTU0MTcxMzA4MCwiYXVkIjoiMTkwLjIzNy40MS42MSIsInVpZCI6IjE1IiwiZXhwIjoxNTQyMzExODgwLCJydGkiOiJhYzJiZDYyNS1hYTcxLTQ3NjItYTkwMC02NTAxNGEwY2VjOGMifQ.LbufEPtU2Y-H0M-3e_ZburFFjN4OjYIb8i7jQoTAmQn_1uhA0jqUrMJ19fZtrlewthrewutyruyptXCasdP', 'HS384');

        $this->assertObjectHasAttribute('key', $valid);
        $this->assertObjectHasAttribute('hash', $valid);
        $this->assertObjectHasAttribute('claims', $valid);

    }

    /**
     * Remove a token from whitelist
     *
     * @throws Exception
     */
    public function testRemove()
    {

        $jwtManager = new JwtManager(false, 'qwerty', 'HS256');

        $claims = [
            'aud' => '190.237.41.61',
            'uid' => '15',
        ];

        $issue = $jwtManager->issue($claims);

        $removed = $jwtManager->removeWhiteList($issue['common']);
        $error = $jwtManager->removeWhiteList('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9easdasyJqdGkiOiIwYWU3NGMwNy1mOTc2LTQyYjEtOTc2Ni1kMTNkY2FlNGQwZmYiLCJpYXQiOjE1NDE3ODE5ODEsIm5iZiI6MTU0MTc4MTk4MSwiYXVkIjoiMTkwLjIzNy40MS42MSIsInVpZCI6IjE1IiwiZXhwIjoxNTQyMzgwNzgxfQ.IKZ91-qWzaOTp5Lm2rZlRnoRQxcKPlpImNJclQhtPQo');

        $this->assertTrue($removed);
        $this->assertStringStartsWith('Error: ', $error);

    }

    /**
     * validate JWT
     *
     * @throws Exception
     */
    public function testValidate()
    {

        $jwtManager = new JwtManager();

        $claims = [
            'aud' => '190.237.41.61',
            'uid' => '15',
        ];

        $issue = $jwtManager->issue($claims);

        $valid = $jwtManager->validate($issue['common']);
        $invalid = $jwtManager->validate('eyJ0eXAi.nf1a2kYZ4DTN4f_yem2sfLDCgEzJOF4O4IKky7ej6gq9rm8Rs7s5ylyIoUJHV8Aq');

        $this->assertTrue($valid);
        $this->assertStringStartsWith('Error: ', $invalid);

    }



}