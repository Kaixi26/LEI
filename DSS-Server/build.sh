#!/bin/env bash

rm -rf target/
mvn package spring-boot:repackage
