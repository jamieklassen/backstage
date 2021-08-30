---
id: life-of-an-entity
title: The Life of an Entity
sidebar_label: The Life of an Entity
# prettier-ignore
description: The life cycle of entities, from being introduced into the catalog, through processing, to being removed again
---

This document gives a high level overview of the catalog backend, and the
technical processes involved in making entities flow through it. It is mainly
aimed at developers who want to understand the internals while installing or
extending the catalog. However, it can be informative for other personas too.

## Key Concepts

The catalog forms a hub of sorts, where entities are ingested from various
authoritative sources and held in a database, subject to automated processing,
and then presented through an API for quick and easy access by Backstage and
others. The most common source is [YAML files](descriptor-format.md) on a
standard format, living in version control systems near the source code of
systems that they describe. Those files are registered with the catalog and
maintained by the respective owners. The catalog makes sure to keep itself up to
date with changes to those files.

The main extension points where developers can customize the catalog are:

- _Entity providers_, that feed initial raw entity data into the catalog,
- _Policies_, that establish baseline rules about the shape of entities,
- _Processors_, that validate, analyze, and mutate the raw entity data into its
  final form.

The high level processes involved are:

- _Ingestion_, where entity providers fetch raw entity data from external
  sources and seed it into the database,
- _Processing_, where the policies and processors continually treat the ingested
  data and may emit both other raw entities (that are also subject to
  processing), errors, relations to other entities, etc.,
- _Stitching_, where all of the data emitted by various processors are stitched
  together into the final output entity.

An entity is not visible to the outside world (through the catalog API), until
it has passed through stitching and landed among the final entities.

![General overview](../../assets/features/catalog/life-of-an-entity_overview.svg)

The details of these processes are described below.

## Ingestion

Each catalog deployment has a number of entity providers installed. They are
responsible for fetching data from external authoritative sources in any way
that they see fit, to translate those into entity objects, and to notify the
database when those entities are added or removed. These are the _unprocessed
entities_ that will be subject to later processing (see below), and they form
the very basis of existence for entities. If there were no entity providers, no
entities would ever enter the system.

The database always keeps track of the set of entities that belong to each
provider; no two providers can try to output the same entity. And when a
provider signals the removal of an entity, then that leads to an _eager
deletion_: the entity and all auxiliary data that it has led to in the database
is immediately purged.

![Ingestion overview](../../assets/features/catalog/life-of-an-entity_ingestion.svg)

There are two providers installed by default: the one that deals with user
registered locations (e.g. URLs to YAML files), and the one that deals with
static locations in the app-config. You can add more third party providers by
passing them to the catalog builder in your backend initialization code, and you
can easily write your own.

An entity provider is a class that implements the `EntityProvider` interface. It
has three main parts:

- The identity: Each provider instance has a unique, stable identifier that the
  database can use to keep track of the originator of each unprocessed entity.
- The connection: During backend startup, each provider is attached to the
  catalog runtime.
- The stream of events: During its lifetime, the provider can issue change
  events to the runtime at any point in time, to modify its set of unprocessed
  entities.

It is entirely up to the provider to choose how and when it produces these
change events. For example, the app-config provider only fires off an update at
startup and then lies dormant. The location database provider does an initial
update at startup, and then small delta updates every time a location database
change is detected. The LDAP provider is driven externally by a timer loop that
occasionally triggers a full update. Some future provider may be entirely event
driven, feeding off an event bus or web hook. There is no magic coordination
among providers; if they need to arrange synchronization or locking among
themselves for example to avoid duplicate work across multiple catalog service
machines, they need to handle that out-of-band.

The entities that are emitted get some coarse validation applied to them, to
ensure that they adhere to the most basic rules of the system. They need to have
a `kind`, a `metadata.name`, and optionally a `metadata.namespace`. Apart from
that, the ingestion stage considers its work done, and stores the unprocessed
entities to be picked up at a later time by the processing system.

## Processing

Every unprocessed entity comes with a timestamp, which tells at what time that
the processing loop should next try to process it. When the entity first
appears, this timestamp is set to "now" - asking for it to be picked up as soon
as possible.

Each catalog deployment has a number of processors installed. They are
responsible for receiving unprocessed entities that the catalog decided are due
for processing, and then running that data through a number of processing
stages. mutating the entity and emitting auxiliary data about it. When all of
that is done, the catalog takes all of that information and stores it as the
processed entity, and errors and relations to other entities separately. Then,
the catalog checks to see what entities are touched by that output, and issues
stitching of those (see below).

There are several stages involved in the processing.

> TODO: More info here

## Stitching

The stitching is currently a fixed process, that cannot be modified or extended.
This means that any modifications you want to make on the final result, has to
happen during ingestion or processing.

> TODO: More info here
