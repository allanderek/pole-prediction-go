-- migrate:up
create view formula_one_events_view as
select 
    id, round, name, season,
    case
        when exists (
            select 1
            from formula_one_sessions
            where event = formula_one_events.id and name = "sprint"
        ) then 1
        else 0 
    end as isSprint,
    cast(( select min(start_time) from formula_one_sessions where event = formula_one_events.id) as text) as start_time
from formula_one_events
;

-- migrate:down
drop view if exists formula_one_events_view
;
