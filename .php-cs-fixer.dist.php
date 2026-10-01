<?php

$finder = (new PhpCsFixer\Finder())
    ->in(__DIR__)
    ->exclude(['var', 'vendor'])
;

return (new PhpCsFixer\Config())
    ->setRules([
        '@Symfony' => true,
        // Keep inline @var docblocks: PHPStan reads them
        'phpdoc_to_comment' => ['ignored_tags' => ['var']],
    ])
    ->setFinder($finder)
;
